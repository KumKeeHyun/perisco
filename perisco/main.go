package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/KumKeeHyun/perisco/perisco/bpf"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS -target bpfel -type sock_key -type conn_event -type close_event -type data_event -no-global-types bpf $BPF_FILES -- -I$BPF_HEADERS

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	ctx, cancel := signal.NotifyContext(
		context.Background(),
		os.Interrupt,
		syscall.SIGTERM)
	defer cancel()

	connCh, closeCh, dataCh, clean := bpf.LoadBpfProgram()
	defer clean()

	go func() {
		for {
			select {
			case connEvent := <-connCh:
				log.Printf("%-15s %-6d   %-15s %-6d  %-10s %-10s",
					connEvent.SockKey.GetSrcIpv4(),
					connEvent.SockKey.Sport,
					connEvent.SockKey.GetDstIpv4(),
					connEvent.SockKey.Dport,
					bpf.IntToEndpointRole(connEvent.EndpointRole),
					"CONN",
				)
			case <-ctx.Done():
				return
			}
		}
	}()

	go func() {
		for {
			select {
			case closeEvent := <-closeCh:
				log.Printf("%-15s %-6d   %-15s %-6d  %-10s %-10s  %-10d %-10d ",
					closeEvent.SockKey.GetSrcIpv4(),
					closeEvent.SockKey.Sport,
					closeEvent.SockKey.GetDstIpv4(),
					closeEvent.SockKey.Dport,
					bpf.IntToEndpointRole(closeEvent.EndpointRole),
					"CLOSE",
					closeEvent.SendBytes,
					closeEvent.RecvBytes,
				)
			case <-ctx.Done():
				return
			}
		}
	}()

	go func() {
		for {
			select {
			case dataEvent := <-dataCh:
				log.Printf("%-15s %-6d   %-15s %-6d  %-10s %-10s\n",
					dataEvent.SockKey.GetSrcIpv4(),
					dataEvent.SockKey.Sport,
					dataEvent.SockKey.GetDstIpv4(),
					dataEvent.SockKey.Dport,
					bpf.IntToEndpointRole(dataEvent.EndpointRole),
					bpf.IntToMsgType(dataEvent.MsgType),
				)
				log.Printf("nrSegs: %d, count: %d, offset: %d, size: %d, msg: %s\n",
					dataEvent.NrSegs,
					dataEvent.Count,
					dataEvent.Offset,
					dataEvent.MsgSize,
					dataEvent.Msg,
				)
			case <-ctx.Done():
				return
			}
		}
	}()

	<-ctx.Done()
}
