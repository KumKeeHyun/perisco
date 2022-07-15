package maps

import (
	"sync"

	"github.com/cilium/ebpf"
)

type Map struct {
	lock sync.Mutex
	m *ebpf.Map
}

func NewMap(m *ebpf.Map) *Map {
	return &Map{
		m: m,
	}
}

type MapOp func(*ebpf.Map) error

func (m *Map) Exec(op MapOp) error {
	m.lock.Lock()
	defer m.lock.Unlock()

	return op(m.m)
}