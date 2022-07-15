package ebpf

import (
	"sync"

	ciliumebpf "github.com/cilium/ebpf"
)

type Map struct {
	lock sync.Mutex
	m *ciliumebpf.Map
}

func NewMap(m *ciliumebpf.Map) *Map {
	return &Map{
		m: m,
	}
}

type MapOp func(*ciliumebpf.Map) error

func (m *Map) Exec(op MapOp) error {
	m.lock.Lock()
	defer m.lock.Unlock()

	return op(m.m)
}