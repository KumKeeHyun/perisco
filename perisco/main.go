package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS -target bpfel -type conn_event -type close_event -type data_event bpf $BPF_FILES -- -I$BPF_HEADERS

type dataEvent struct {
	SockKey       bpfSockKey
	EndpointRole  int32
	MsgType       int32
	Msg           [4096]byte
	_             [4]byte
	MsgSize       uint64
	OriginMsgSize uint64
}

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	ctx, cancel := signal.NotifyContext(
		context.Background(),
		os.Interrupt,
		syscall.SIGTERM)
	defer cancel()

	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	acceptLink, err := link.AttachTracing(link.TracingOptions{
		Program: objs.bpfPrograms.InetAccept,
	})
	if err != nil {
		log.Fatal(err)
	}
	defer acceptLink.Close()

	connectLink, err := link.AttachTracing(link.TracingOptions{
		Program: objs.bpfPrograms.TcpConnect,
	})
	if err != nil {
		log.Fatal(err)
	}
	defer connectLink.Close()

	sendLink, err := link.AttachTracing(link.TracingOptions{
		Program: objs.bpfPrograms.TcpSendmsg,
	})
	if err != nil {
		log.Fatal(err)
	}
	defer sendLink.Close()

	recvLink, err := link.AttachTracing(link.TracingOptions{
		Program: objs.bpfPrograms.TcpRecvmsg,
	})
	if err != nil {
		log.Fatal(err)
	}
	defer recvLink.Close()

	closeLink, err := link.AttachTracing(link.TracingOptions{
		Program: objs.bpfPrograms.TcpClose,
	})
	if err != nil {
		log.Fatal(err)
	}
	defer closeLink.Close()

	rd, err := ringbuf.NewReader(objs.bpfMaps.ConnEvents)
	if err != nil {
		log.Fatalf("opening ringbuf reader: %s", err)
	}
	defer rd.Close()

	go func() {
		var connEvent bpfConnEvent
		for {
			record, err := rd.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					log.Println("received signal, exiting..")
					return
				}
				log.Printf("reading from reader: %s", err)
				continue
			}

			if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &connEvent); err != nil {
				log.Printf("parsing ringbuf event: %s", err)
				continue
			}

			log.Printf("%-15s %-6d   %-15s %-6d  %-10s %-10s",
				intToIP(connEvent.SockKey.getSrcIpv4()),
				connEvent.SockKey.Sport,
				intToIP(connEvent.SockKey.getDstIpv4()),
				connEvent.SockKey.Dport,
				intToEndpointRole(connEvent.EndpointRole),
				"CONN",
			)
		}
	}()

	closeRd, err := ringbuf.NewReader(objs.bpfMaps.CloseEvents)
	if err != nil {
		log.Fatalf("opening ringbuf reader: %s", err)
	}
	defer closeRd.Close()

	go func() {
		var closeEvent bpfCloseEvent
		for {
			record, err := closeRd.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					log.Println("received signal, exiting..")
					return
				}
				log.Printf("reading from reader: %s", err)
				continue
			}

			if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &closeEvent); err != nil {
				log.Printf("parsing ringbuf event: %s", err)
				continue
			}

			log.Printf("%-15s %-6d   %-15s %-6d  %-10s %-10s  %-10d %-10d ",
				intToIP(closeEvent.SockKey.getSrcIpv4()),
				closeEvent.SockKey.Sport,
				intToIP(closeEvent.SockKey.getDstIpv4()),
				closeEvent.SockKey.Dport,
				intToEndpointRole(closeEvent.EndpointRole),
				"CLOSE",
				closeEvent.SendBytes,
				closeEvent.RecvBytes,
			)
		}
	}()

	dataRd, err := ringbuf.NewReader(objs.bpfMaps.DataEvents)
	if err != nil {
		log.Fatalf("opening ringbuf reader: %s", err)
	}
	defer dataRd.Close()

	go func() {
		var dataEvent dataEvent
		for {
			record, err := dataRd.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					log.Println("received signal, exiting..")
					return
				}
				log.Printf("reading from reader: %s", err)
				continue
			}

			if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &dataEvent); err != nil {
				log.Printf("parsing ringbuf event: %s", err)
				continue
			}

			log.Printf("%-15s %-6d   %-15s %-6d  %-10s %-10s\n",
				intToIP(dataEvent.SockKey.getSrcIpv4()),
				dataEvent.SockKey.Sport,
				intToIP(dataEvent.SockKey.getDstIpv4()),
				dataEvent.SockKey.Dport,
				intToEndpointRole(dataEvent.EndpointRole),
				intToMsgType(dataEvent.MsgType),
			)
			log.Printf("originSize: %d size: %d, msg: %s\n",
				dataEvent.OriginMsgSize,
				dataEvent.MsgSize,
				dataEvent.Msg,
			)
		}
	}()

	<-ctx.Done()
}

func (sk *bpfSockKey) getSrcIpv4() uint32 {
	return sk.Sip.Addr.Pad1
}

func (sk *bpfSockKey) getDstIpv4() uint32 {
	return sk.Dip.Addr.Pad1
}

// intToIP converts IPv4 number to net.IP
func intToIP(ipNum uint32) net.IP {
	ip := make(net.IP, 4)
	binary.LittleEndian.PutUint32(ip, ipNum)
	return ip
}

func intToEndpointRole(roleNum int32) string {
	switch roleNum {
	case 1 << 0:
		return "CLIENT"
	case 1 << 1:
		return "SERVER"
	default:
		return "UNKNOWN"
	}
}

func intToMsgType(msgType int32) string {
	switch msgType {
	case 0:
		return "REQUEST"
	case 1:
		return "RESPONSE"
	default:
		return "UNKNOWN"
	}
}
