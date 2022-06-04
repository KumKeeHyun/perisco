package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/KumKeeHyun/perisco/perisco/bpf"
	"github.com/KumKeeHyun/perisco/pkg/protocols"
	"github.com/cilium/ebpf/rlimit"
)

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
				log.Printf("%-15s %-6d   %-15s %-6d  %-10s",
					connEvent.SockKey.GetSrcIpv4(),
					connEvent.SockKey.Sport,
					connEvent.SockKey.GetDstIpv4(),
					connEvent.SockKey.Dport,
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
				log.Printf("%-15s %-6d   %-15s %-6d  %-10s  %-10d %-10d ",
					closeEvent.SockKey.GetSrcIpv4(),
					closeEvent.SockKey.Sport,
					closeEvent.SockKey.GetDstIpv4(),
					closeEvent.SockKey.Dport,
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
				if dataEvent.SockKey.Dport == 443 {
					continue
				}

				// filter response
				// if dataEvent.MsgType != 0 {
				// 	continue
				// }

				// rawLogging(&dataEvent)
				parseProto(&dataEvent, &protocols.Http1Parser{})
				parseProto(&dataEvent, &protocols.Http2Parser{})

			case <-ctx.Done():
				return
			}
		}
	}()

	<-ctx.Done()
}

func rawLogging(dataEvent *bpf.BpfDataEvent) {
	log.Printf("%-15s %-6d   %-15s %-6d  %-10s %d\nsize: %d, msg: %s\n",
		dataEvent.SockKey.GetSrcIpv4(),
		dataEvent.SockKey.Sport,
		dataEvent.SockKey.GetDstIpv4(),
		dataEvent.SockKey.Dport,
		bpf.IntToMsgType(dataEvent.MsgType),
		dataEvent.SockKey.Family,
		dataEvent.MsgSize,
		dataEvent.Msg[:dataEvent.MsgSize],
	)
}

func parseProto(event *bpf.BpfDataEvent, parser protocols.Parser) {
	if event.MsgType == 0 {
		req, err := parser.ParseRequest(event.Msg[:event.MsgSize])
		if err != nil {
			return
		}

		log.Printf("%-15s %-6d   %-15s %-6d  %-10s pid: %-5d\n %s\n",
			event.SockKey.GetSrcIpv4(),
			event.SockKey.Sport,
			event.SockKey.GetDstIpv4(),
			event.SockKey.Dport,
			bpf.IntToMsgType(event.MsgType),
			event.SockKey.Pid,
			req.String(),
		)
	} else if event.MsgType == 1 {
		resp, err := parser.ParseResponse(event.Msg[:event.MsgSize])
		if err != nil {
			return
		}

		log.Printf("%-15s %-6d   %-15s %-6d  %-10s pid: %-5d\n %s\n",
			event.SockKey.GetSrcIpv4(),
			event.SockKey.Sport,
			event.SockKey.GetDstIpv4(),
			event.SockKey.Dport,
			bpf.IntToMsgType(event.MsgType),
			event.SockKey.Pid,
			resp.String(),
		)
	}
}
