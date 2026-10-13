// Copyright 2024 Redpanda Data, Inc.
//
// Licensed as a Redpanda Enterprise file under the Redpanda Community
// License (the "License"); you may not use this file except in compliance with
// the License. You may obtain a copy of the License at
//
// https://github.com/redpanda-data/connect/blob/main/licenses/rcl.md

package secrets

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"regexp"
	"strings"

	// Imported for mysql.NewConfig and to register the "mysql" driver with
	// database/sql via its init function.
	"github.com/go-sql-driver/mysql"
)

// mysqlSecretsClient looks secrets up from a MySQL table. It targets the
// Captain Wallet `dynamic_configurations` table by default, where each secret
// is a (app, key, value) row optionally scoped by account_id, but every table
// and column name is configurable through the secrets URN.
type mysqlSecretsClient struct {
	logger *slog.Logger
	db     *sql.DB

	// query is precomputed from the URN. It selects the value column and binds
	// the lookup key as the first placeholder, followed by fixedArgs.
	query     string
	fixedArgs []any
}

func (m *mysqlSecretsClient) lookup(ctx context.Context, key string) (string, bool) {
	args := make([]any, 0, len(m.fixedArgs)+1)
	args = append(args, key)
	args = append(args, m.fixedArgs...)

	var value string
	if err := m.db.QueryRowContext(ctx, m.query, args...).Scan(&value); err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			// An error that isn't due to the key not being found gets logged.
			m.logger.With("error", err, "key", key).Error("Failed to look up secret")
		}
		return "", false
	}
	return value, true
}

// validSQLIdentifier guards table/column names that are interpolated directly
// into the query (SQL cannot bind identifiers as parameters). Values such as
// the lookup key, app and account_id are always bound and therefore safe.
var validSQLIdentifier = regexp.MustCompile(`^[A-Za-z0-9_]+$`)

// reservedMySQLParams are URN query parameters consumed by this provider and
// therefore not forwarded to the MySQL driver connection string.
var reservedMySQLParams = map[string]struct{}{
	"table":       {},
	"key_col":     {},
	"value_col":   {},
	"app_col":     {},
	"account_col": {},
	"app":         {},
	"account_id":  {},
}

// newMySQLSecretsLookup builds a LookupFn backed by a MySQL table.
//
// The URN has the form:
//
//	mysql://user:pass@host:3306/dbname?app=sftp&account_id=123
//
// Supported query parameters (all optional, defaults match the Captain Wallet
// `dynamic_configurations` schema):
//
//	table       - table name                        (default "dynamic_configurations")
//	key_col     - column holding the lookup key      (default "key")
//	value_col   - column holding the secret value    (default "value")
//	app_col     - column holding the app scope        (default "app")
//	account_col - column holding the account scope    (default "account_id")
//	app         - when set, filters app_col = <app>
//	account_id  - when set, filters account_col = <account_id>;
//	              when omitted, filters account_col IS NULL (global scope)
//
// Any other query parameters are forwarded verbatim to the MySQL driver (e.g.
// tls, parseTime, timeout).
func newMySQLSecretsLookup(ctx context.Context, logger *slog.Logger, u *url.URL) (LookupFn, error) {
	q := u.Query()

	table := valueOrDefault(q.Get("table"), "dynamic_configurations")
	keyCol := valueOrDefault(q.Get("key_col"), "key")
	valueCol := valueOrDefault(q.Get("value_col"), "value")
	appCol := valueOrDefault(q.Get("app_col"), "app")
	accountCol := valueOrDefault(q.Get("account_col"), "account_id")

	for _, id := range []string{table, keyCol, valueCol, appCol, accountCol} {
		if !validSQLIdentifier.MatchString(id) {
			return nil, fmt.Errorf("invalid SQL identifier %q in mysql secrets URN", id)
		}
	}

	cfg := mysql.NewConfig()
	cfg.User = u.User.Username()
	cfg.Passwd, _ = u.User.Password()
	cfg.Net = "tcp"
	cfg.Addr = u.Host
	cfg.DBName = strings.TrimPrefix(u.Path, "/")

	// Forward any non-reserved query parameters to the driver connection.
	params := map[string]string{}
	for k, vs := range q {
		if _, ok := reservedMySQLParams[k]; ok {
			continue
		}
		if len(vs) > 0 {
			params[k] = vs[0]
		}
	}
	if len(params) > 0 {
		cfg.Params = params
	}

	db, err := sql.Open("mysql", cfg.FormatDSN())
	if err != nil {
		return nil, fmt.Errorf("failed to open mysql secrets store: %w", err)
	}
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("failed to connect to mysql secrets store: %w", err)
	}

	var sb strings.Builder
	fmt.Fprintf(&sb, "SELECT `%s` FROM `%s` WHERE `%s` = ?", valueCol, table, keyCol)

	var fixedArgs []any
	if app := q.Get("app"); app != "" {
		fmt.Fprintf(&sb, " AND `%s` = ?", appCol)
		fixedArgs = append(fixedArgs, app)
	}
	if q.Has("account_id") {
		fmt.Fprintf(&sb, " AND `%s` = ?", accountCol)
		fixedArgs = append(fixedArgs, q.Get("account_id"))
	} else {
		fmt.Fprintf(&sb, " AND `%s` IS NULL", accountCol)
	}
	sb.WriteString(" LIMIT 1")

	m := &mysqlSecretsClient{
		logger:    logger,
		db:        db,
		query:     sb.String(),
		fixedArgs: fixedArgs,
	}
	return m.lookup, nil
}

func valueOrDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}
