// Code generated by bpf2go; DO NOT EDIT.
//go:build 386 || amd64 || amd64p32 || arm || arm64 || mips64le || mips64p32le || mipsle || ppc64le || riscv64
// +build 386 amd64 amd64p32 arm arm64 mips64le mips64p32le mipsle ppc64le riscv64

package bpf

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

type bpfEndpointKey struct {
	IpAddr    [16]int8
	IpVersion int32
	Port      uint32
	Pid       uint32
}

type bpfIp struct {
	Source      [16]int8
	Destination [16]int8
	IpVersion   int32
}

type bpfIpNetwork struct {
	IpAddr [16]int8
	IpMask [16]int8
}

type bpfIpNetworks struct {
	Data [5]bpfIpNetwork
	Size uint32
}

type bpfLayer4 struct {
	SourcePort      uint32
	DestinationPort uint32
}

type bpfMsgEvent struct {
	Msg       [4096]int8
	SockKey   bpfSockKey
	Timestamp uint64
	FlowType  int32
	Protocol  int32
	MsgSize   uint32
	_         [4]byte
}

type bpfSockKey struct {
	Ip  bpfIp
	L4  bpfLayer4
	Pid uint32
}

// loadBpf returns the embedded CollectionSpec for bpf.
func loadBpf() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_BpfBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load bpf: %w", err)
	}

	return spec, err
}

// loadBpfObjects loads bpf and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//     *bpfObjects
//     *bpfPrograms
//     *bpfMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func loadBpfObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := loadBpf()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// bpfSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type bpfSpecs struct {
	bpfProgramSpecs
	bpfMapSpecs
}

// bpfSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type bpfProgramSpecs struct {
	FentrySockRecvmsg *ebpf.ProgramSpec `ebpf:"fentry_sock_recvmsg"`
	FentrySockSendmsg *ebpf.ProgramSpec `ebpf:"fentry_sock_sendmsg"`
	FexitInetAccept   *ebpf.ProgramSpec `ebpf:"fexit_inet_accept"`
	FexitSockRecvmsg  *ebpf.ProgramSpec `ebpf:"fexit_sock_recvmsg"`
}

// bpfMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type bpfMapSpecs struct {
	NetworkFilter *ebpf.MapSpec `ebpf:"network_filter"`
	ProtocolMap   *ebpf.MapSpec `ebpf:"protocol_map"`
	RecvmsgArgMap *ebpf.MapSpec `ebpf:"recvmsg_arg_map"`
	RecvmsgEvents *ebpf.MapSpec `ebpf:"recvmsg_events"`
	SendmsgEvents *ebpf.MapSpec `ebpf:"sendmsg_events"`
	ServerMap     *ebpf.MapSpec `ebpf:"server_map"`
}

// bpfObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to loadBpfObjects or ebpf.CollectionSpec.LoadAndAssign.
type bpfObjects struct {
	bpfPrograms
	bpfMaps
}

func (o *bpfObjects) Close() error {
	return _BpfClose(
		&o.bpfPrograms,
		&o.bpfMaps,
	)
}

// bpfMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to loadBpfObjects or ebpf.CollectionSpec.LoadAndAssign.
type bpfMaps struct {
	NetworkFilter *ebpf.Map `ebpf:"network_filter"`
	ProtocolMap   *ebpf.Map `ebpf:"protocol_map"`
	RecvmsgArgMap *ebpf.Map `ebpf:"recvmsg_arg_map"`
	RecvmsgEvents *ebpf.Map `ebpf:"recvmsg_events"`
	SendmsgEvents *ebpf.Map `ebpf:"sendmsg_events"`
	ServerMap     *ebpf.Map `ebpf:"server_map"`
}

func (m *bpfMaps) Close() error {
	return _BpfClose(
		m.NetworkFilter,
		m.ProtocolMap,
		m.RecvmsgArgMap,
		m.RecvmsgEvents,
		m.SendmsgEvents,
		m.ServerMap,
	)
}

// bpfPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadBpfObjects or ebpf.CollectionSpec.LoadAndAssign.
type bpfPrograms struct {
	FentrySockRecvmsg *ebpf.Program `ebpf:"fentry_sock_recvmsg"`
	FentrySockSendmsg *ebpf.Program `ebpf:"fentry_sock_sendmsg"`
	FexitInetAccept   *ebpf.Program `ebpf:"fexit_inet_accept"`
	FexitSockRecvmsg  *ebpf.Program `ebpf:"fexit_sock_recvmsg"`
}

func (p *bpfPrograms) Close() error {
	return _BpfClose(
		p.FentrySockRecvmsg,
		p.FentrySockSendmsg,
		p.FexitInetAccept,
		p.FexitSockRecvmsg,
	)
}

func _BpfClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//go:embed bpf_bpfel.o
var _BpfBytes []byte
