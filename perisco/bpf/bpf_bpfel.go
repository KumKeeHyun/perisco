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

type bpfCloseEvent struct {
	SockKey   bpfSockKey
	SendBytes uint64
	RecvBytes uint64
}

type bpfConnEvent struct{ SockKey bpfSockKey }

type bpfDataEvent struct {
	Msg       [4096]int8
	SockKey   bpfSockKey
	MsgType   int32
	ProtoType int32
	MsgSize   uint32
}

type bpfSockKey struct {
	Sip struct {
		Addr struct {
			Pad1 uint32
			Pad2 uint32
			Pad3 uint32
			Pad4 uint32
		}
	}
	Dip struct {
		Addr struct {
			Pad1 uint32
			Pad2 uint32
			Pad3 uint32
			Pad4 uint32
		}
	}
	Sport  uint32
	Dport  uint32
	Pid    uint32
	Family uint8
	Pad1   uint8
	Pad2   uint16
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
	FexitSockRecvmsg  *ebpf.ProgramSpec `ebpf:"fexit_sock_recvmsg"`
	InetAccept        *ebpf.ProgramSpec `ebpf:"inet_accept"`
	InetShutdown      *ebpf.ProgramSpec `ebpf:"inet_shutdown"`
}

// bpfMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type bpfMapSpecs struct {
	CloseEvents   *ebpf.MapSpec `ebpf:"close_events"`
	ConnEvents    *ebpf.MapSpec `ebpf:"conn_events"`
	ConnInfoMap   *ebpf.MapSpec `ebpf:"conn_info_map"`
	DataEvents    *ebpf.MapSpec `ebpf:"data_events"`
	RecvmsgArgMap *ebpf.MapSpec `ebpf:"recvmsg_arg_map"`
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
	CloseEvents   *ebpf.Map `ebpf:"close_events"`
	ConnEvents    *ebpf.Map `ebpf:"conn_events"`
	ConnInfoMap   *ebpf.Map `ebpf:"conn_info_map"`
	DataEvents    *ebpf.Map `ebpf:"data_events"`
	RecvmsgArgMap *ebpf.Map `ebpf:"recvmsg_arg_map"`
}

func (m *bpfMaps) Close() error {
	return _BpfClose(
		m.CloseEvents,
		m.ConnEvents,
		m.ConnInfoMap,
		m.DataEvents,
		m.RecvmsgArgMap,
	)
}

// bpfPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadBpfObjects or ebpf.CollectionSpec.LoadAndAssign.
type bpfPrograms struct {
	FentrySockRecvmsg *ebpf.Program `ebpf:"fentry_sock_recvmsg"`
	FentrySockSendmsg *ebpf.Program `ebpf:"fentry_sock_sendmsg"`
	FexitSockRecvmsg  *ebpf.Program `ebpf:"fexit_sock_recvmsg"`
	InetAccept        *ebpf.Program `ebpf:"inet_accept"`
	InetShutdown      *ebpf.Program `ebpf:"inet_shutdown"`
}

func (p *bpfPrograms) Close() error {
	return _BpfClose(
		p.FentrySockRecvmsg,
		p.FentrySockSendmsg,
		p.FexitSockRecvmsg,
		p.InetAccept,
		p.InetShutdown,
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
