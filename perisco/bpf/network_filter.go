package bpf

import (
	"context"
	"fmt"
	"net"

	"github.com/cilium/ebpf"
)

func NewNetworkFilter(m *ebpf.Map) *NetworkFilter {
	ctx, cancel := context.WithCancel(context.Background())
	cm := NewConcurrentMap(ctx, m)

	return &NetworkFilter{
		cm:     cm,
		ctx:    ctx,
		cancel: cancel,
	}
}

type NetworkFilter struct {
	cm *concurrentMap

	ctx    context.Context
	cancel context.CancelFunc
}

func (nf *NetworkFilter) Update(cidrs []string) error {
	if len(cidrs) > MAX_NET_FILTER_SIZE {
		return fmt.Errorf("network filter cannot contain cidrs more than %d", MAX_NET_FILTER_SIZE)
	}
	
	bpfIpNets := BpfIpNetworks{
		Size: uint32(len(cidrs)),
	}
	for i, cidr := range cidrs {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			return fmt.Errorf("failed to parse cidr: %s", err)
		}
		bpfIpNets.Data[i] = ipNet2BpfIpNet(ipNet)
	}

	if err := nf.update(&bpfIpNets); err != nil {
		return fmt.Errorf("failed to update map: %s", err)
	}
	
	return nil
}

func ipNet2BpfIpNet(ipNet *net.IPNet) (bpfIpNet BpfIpNetwork) {
	copy(bpfIpNet.IpAddr[:], ipNet.IP)
	copy(bpfIpNet.IpMask[:], ipNet.Mask)
	return 
}

func (nf *NetworkFilter) update(networks *BpfIpNetworks) error {
	err := nf.cm.Do(func(m *ebpf.Map) error {
		return m.Update(&NET_FILTER_KEY, networks, ebpf.UpdateAny)
	})
	if err != nil {
		return err
	}
	return nil
}

func (nf *NetworkFilter) Close() error {
	nf.cancel()
	return nf.ctx.Err()
}