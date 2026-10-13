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
	"fmt"
	"log/slog"
	"net/url"
	"testing"
	"time"

	"github.com/ory/dockertest/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	_ "github.com/redpanda-data/benthos/v4/public/components/pure"
	"github.com/redpanda-data/benthos/v4/public/service/integration"
)

func TestIntegrationMySQLSecrets(t *testing.T) {
	integration.CheckSkip(t)
	t.Parallel()

	pool, err := dockertest.NewPool("")
	require.NoError(t, err)
	pool.MaxWait = 3 * time.Minute

	resource, err := pool.RunWithOptions(&dockertest.RunOptions{
		Repository:   "mysql",
		ExposedPorts: []string{"3306/tcp"},
		Env: []string{
			"MYSQL_USER=testuser",
			"MYSQL_PASSWORD=testpass",
			"MYSQL_DATABASE=testdb",
			"MYSQL_RANDOM_ROOT_PASSWORD=yes",
		},
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		assert.NoError(t, pool.Purge(resource))
	})

	port := resource.GetPort("3306/tcp")
	dsn := fmt.Sprintf("testuser:testpass@tcp(localhost:%s)/testdb", port)

	var db *sql.DB
	require.NoError(t, pool.Retry(func() error {
		if db, err = sql.Open("mysql", dsn); err != nil {
			return err
		}
		return db.Ping()
	}))
	t.Cleanup(func() { _ = db.Close() })

	// Mirror the Captain Wallet dynamic_configurations schema. `key` is a
	// reserved word, hence the backticks.
	_, err = db.Exec("CREATE TABLE `dynamic_configurations` (" +
		"`id` BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY," +
		"`account_id` INT UNSIGNED NULL," +
		"`app` VARCHAR(255) NOT NULL," +
		"`key` VARCHAR(255) NOT NULL," +
		"`value` TEXT NULL," +
		"`updated_by` VARCHAR(255) NULL," +
		"`created_at` TIMESTAMP NULL," +
		"`updated_at` TIMESTAMP NULL)")
	require.NoError(t, err)

	insert := func(accountID *int, app, key, value string) {
		_, err := db.Exec("INSERT INTO `dynamic_configurations` (`account_id`, `app`, `key`, `value`) VALUES (?, ?, ?, ?)",
			accountID, app, key, value)
		require.NoError(t, err)
	}

	acc := 123
	insert(&acc, "sftp", "sftp_prod_password", "hunter2")   // account-scoped
	insert(nil, "sftp", "sftp_prod_host", "sftp.acme.com")  // global scope
	insert(nil, "other", "sftp_prod_host", "wrong.example") // different app, must not leak

	ctx, done := context.WithTimeout(context.Background(), time.Minute)
	defer done()

	t.Run("account scoped lookup", func(t *testing.T) {
		urn := fmt.Sprintf("mysql://testuser:testpass@localhost:%s/testdb?app=sftp&account_id=123", port)
		lookup, err := parseSecretsLookupURN(ctx, slog.Default(), urn)
		require.NoError(t, err)

		v, ok := lookup(ctx, "sftp_prod_password")
		assert.True(t, ok)
		assert.Equal(t, "hunter2", v)

		// Global-scoped row is not visible when an account is requested.
		_, ok = lookup(ctx, "sftp_prod_host")
		assert.False(t, ok)

		_, ok = lookup(ctx, "missing")
		assert.False(t, ok)
	})

	t.Run("global scoped lookup", func(t *testing.T) {
		urn := fmt.Sprintf("mysql://testuser:testpass@localhost:%s/testdb?app=sftp", port)
		lookup, err := parseSecretsLookupURN(ctx, slog.Default(), urn)
		require.NoError(t, err)

		v, ok := lookup(ctx, "sftp_prod_host")
		assert.True(t, ok)
		assert.Equal(t, "sftp.acme.com", v)

		// account-scoped row is not visible without an account.
		_, ok = lookup(ctx, "sftp_prod_password")
		assert.False(t, ok)
	})

	t.Run("app scoping isolates keys", func(t *testing.T) {
		urn := fmt.Sprintf("mysql://testuser:testpass@localhost:%s/testdb?app=other", port)
		lookup, err := parseSecretsLookupURN(ctx, slog.Default(), urn)
		require.NoError(t, err)

		v, ok := lookup(ctx, "sftp_prod_host")
		assert.True(t, ok)
		assert.Equal(t, "wrong.example", v)
	})
}

func TestMySQLSecretsInvalidIdentifier(t *testing.T) {
	u, err := url.Parse("mysql://u:p@localhost:3306/db?value_col=value%3BDROP+TABLE+x")
	require.NoError(t, err)

	_, err = newMySQLSecretsLookup(context.Background(), slog.Default(), u)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid SQL identifier")
}
