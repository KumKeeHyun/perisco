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
				log.Printf("%s  %-10s",
					connEvent.SockKey.String(),
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
				log.Printf("%s  %-10s  %-10d %-10d ",
					closeEvent.SockKey.String(),
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
	log.Printf("%s  %-10s\nsize: %d, msg: %s\n",
		dataEvent.SockKey.String(),
		dataEvent.FlowType.String(),
		dataEvent.MsgSize,
		dataEvent.Msg[:dataEvent.MsgSize],
	)
}

func parseProto(event *bpf.BpfDataEvent, parser protocols.Parser) {
	if event.FlowType == bpf.REQUEST {
		req, err := parser.ParseRequest(event.Msg[:event.MsgSize])
		if err != nil {
			return
		}

		log.Printf("%s  %-10s\n %s\n",
			event.SockKey.String(),
			event.FlowType.String(),
			req.String(),
		)
	} else if event.FlowType == bpf.RESPONSE {
		resp, err := parser.ParseResponse(event.Msg[:event.MsgSize])
		if err != nil {
			return
		}

		log.Printf("%s  %-10s\n %s\n",
			event.SockKey.String(),
			event.FlowType.String(),
			resp.String(),
		)
	}
}
