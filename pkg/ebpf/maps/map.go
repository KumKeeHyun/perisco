package maps

import (
	"sync"

	"github.com/cilium/ebpf"
)

type Map interface {
	Exec(op MapOp) error
}

type ebpfMap struct {
	lock sync.Mutex
	m    *ebpf.Map
}

var _ Map = &ebpfMap{}

func NewMap(m *ebpf.Map) *ebpfMap {
	return &ebpfMap{
		m: m,
	}
}

type MapOp func(*ebpf.Map) error

func (m *ebpfMap) Exec(op MapOp) error {
	m.lock.Lock()
	defer m.lock.Unlock()

	return op(m.m)
}

type MockMap struct {
}

var _ Map = &MockMap{}

// Exec implements Map
func (*MockMap) Exec(op MapOp) error {
	return nil
}

