package amqpcw

type ConnectTaskRecordEvent struct {
	ClassName string `php:"className",default:"CaptainWallet\\Integration\\Connect\\ConnectTaskRecordEvent"`
	Account   string `php:"account"`
	TaskName  string `php:"taskName"`
	Offset    int64  `php:"offset"`
	Record    any    `php:"record"`
}
