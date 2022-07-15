package maps

import (
	"fmt"

	"github.com/KumKeeHyun/perisco/pkg/ebpf/types"
	"github.com/cilium/ebpf"
)

type ProtocolMap struct {
	m *Map
}

func NewProtocolMap(m *ebpf.Map) *ProtocolMap {
	return &ProtocolMap{
		m: NewMap(m),
	}
}

func (pm *ProtocolMap) Detect(sk types.SockKey, proto types.ProtocolType) error {
	if proto == types.PROTO_UNKNOWN || proto == types.PROTO_SKIP {
			return fmt.Errorf("cannot register unknown or skip manually")
	}
	ek := sk.ToEndpointKey()
	return pm.registerProto(ek, proto)
}

func (pm *ProtocolMap) Skip(sk types.SockKey) error {
	ek := sk.ToEndpointKey()
	return pm.registerProto(ek, types.PROTO_SKIP)
}

func (pm *ProtocolMap) registerProto(ek types.EndpointKey, proto types.ProtocolType) error {
	err := pm.m.Exec(func(m *ebpf.Map) error {
		return m.Update(&ek, &proto, ebpf.UpdateAny)
	})
	if err != nil {
		return fmt.Errorf("failed to update protocol map: %v", err)
	}
	return nil
}
