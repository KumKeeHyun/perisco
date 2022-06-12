package bpf

import (
	"context"

	"github.com/cilium/ebpf"
)

func NewConcurrentMap(c context.Context, m *ebpf.Map) *concurrentMap {
	ctx, cancel := context.WithCancel(c)
	cm := &concurrentMap{
		bpfMap:  m,
		reqChan: make(chan *mapOpReq),
		ctx:     ctx,
		cancel:  cancel,
	}
	go cm.run()

	return cm
}

type MapOp func(*ebpf.Map) error

type mapOpReq struct {
	op   MapOp
	resp chan error
}

type concurrentMap struct {
	bpfMap  *ebpf.Map
	reqChan chan *mapOpReq

	ctx    context.Context
	cancel context.CancelFunc
}

func (m *concurrentMap) run() {
	for {
		select {
		case req := <-m.reqChan:
			req.resp <- req.op(m.bpfMap)
			close(req.resp)
		case <-m.ctx.Done():
			return
		}
	}
}

func (m *concurrentMap) Do(op MapOp) error {
	req := &mapOpReq{
		op:   op,
		resp: make(chan error),
	}
	m.reqChan <- req
	return <-req.resp
}

func (m *concurrentMap) Close() error {
	m.cancel()
	return m.ctx.Err()
}
