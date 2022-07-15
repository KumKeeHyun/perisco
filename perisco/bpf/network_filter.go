package bpf

import (
	"fmt"

	periscoebpf "github.com/KumKeeHyun/perisco/pkg/ebpf"
	"github.com/KumKeeHyun/perisco/pkg/ebpf/types"
	"github.com/cilium/ebpf"
)

var NET_FILTER_KEY uint32 = 0

func NewNetworkFilter(m *ebpf.Map) *NetworkFilter {
	return &NetworkFilter{
		m: periscoebpf.NewMap(m),
	}
}

type NetworkFilter struct {
	m *periscoebpf.Map
}

func (nf *NetworkFilter) RegisterCIDRs(cidrs []string) error {
	ins, err := types.ParseCIDRs(cidrs)
	if err != nil {
		return err
	}

	err = nf.m.Exec(func(m *ebpf.Map) error {
		return m.Update(&NET_FILTER_KEY, &ins, ebpf.UpdateAny)
	})
	if err != nil {
		return fmt.Errorf("failed to update network filter map: %v", err)
	}
	return nil
}
