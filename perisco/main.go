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

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS -target bpfel -type conn_info bpf $BPF_FILES -- -I$BPF_HEADERS

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

	rd, err := ringbuf.NewReader(objs.bpfMaps.ConnEvents)
	if err != nil {
		log.Fatalf("opening ringbuf reader: %s", err)
	}
	defer rd.Close()

	go func() {
		var connInfo bpfConnInfo
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

			if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &connInfo); err != nil {
				log.Printf("parsing ringbuf event: %s", err)
				continue
			}

			log.Printf("%-15s %-6d    %-15s %-6d  %-10s",
				intToIP(connInfo.getSrcIpv4()),
				connInfo.SockKey.Sport,
				intToIP(connInfo.getDstIpv4()),
				connInfo.SockKey.Dport,
				intToEndpointRole(connInfo.EndpointRole),
			)
		}
	}()

	<-ctx.Done()
}

func (ci *bpfConnInfo) getSrcIpv4() uint32 {
	return ci.SockKey.Sip.Addr.Pad1
}

func (ci *bpfConnInfo) getDstIpv4() uint32 {
	return ci.SockKey.Dip.Addr.Pad1
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
