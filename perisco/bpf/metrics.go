package bpf

import (
	"github.com/prometheus/client_golang/prometheus"
)

var (
	msgEventPoolNew = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "perisco_debugging",
		Subsystem: "bpf",
		Name:      "msg_event_pool_new",
		Help:      "The new count in msg event pool.",
	})
	msgEventPoolPut = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "perisco_debugging",
		Subsystem: "bpf",
		Name:      "msg_event_pool_put",
		Help:      "The put count in msg event pool.",
	})
	sendmsgEvents = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "perisco_debugging",
		Subsystem: "bpf",
		Name:      "sendmsg_event",
		Help:      "The count of sendmsg event.",
	})
	recvmsgEvents = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "perisco_debugging",
		Subsystem: "bpf",
		Name:      "recvmsg_event",
		Help:      "The count of recvmsg event.",
	})
)

func init() {
	prometheus.MustRegister(msgEventPoolNew)
	prometheus.MustRegister(msgEventPoolPut)
	prometheus.MustRegister(sendmsgEvents)
	prometheus.MustRegister(recvmsgEvents)
}
