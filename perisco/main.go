package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/KumKeeHyun/perisco/perisco/bpf"
	"github.com/KumKeeHyun/perisco/perisco/config"
	"github.com/KumKeeHyun/perisco/pkg/protocols"
	"github.com/cilium/ebpf/rlimit"
)

func main() {

	config, err := config.LoadConfig()
	if err != nil {
		log.Fatal(err)
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	ctx, cancel := signal.NotifyContext(
		context.Background(),
		os.Interrupt,
		syscall.SIGTERM)
	defer cancel()

	recvCh, sendCh, netFilterMap, clean := bpf.LoadBpfProgram()
	defer clean()

	nf := bpf.NewNetworkFilter(netFilterMap)
	defer nf.Close()

	if err := nf.Update(config.CidrSlice()); err != nil {
		log.Fatal(err)
	}
	log.Printf("network filter: %v", config.CidrSlice())

	go func() {
		for {
			select {
			case dataEvent := <-recvCh:

				// rawLogging(&dataEvent)
				parseProto(dataEvent, &protocols.Http1Parser{})
				parseProto(dataEvent, &protocols.Http2Parser{})

			case <-ctx.Done():
				return
			}
		}
	}()

	go func() {
		for {
			select {
			case dataEvent := <-sendCh:

				// rawLogging(&dataEvent)
				parseProto(dataEvent, &protocols.Http1Parser{})
				parseProto(dataEvent, &protocols.Http2Parser{})

			case <-ctx.Done():
				return
			}
		}
	}()

	<-ctx.Done()
}

func rawLogging(dataEvent *bpf.MsgEvent) {
	log.Printf("%s  %-10s\nsize: %d, msg: %s\n",
		dataEvent.SockKey.String(),
		dataEvent.FlowType.String(),
		dataEvent.MsgSize,
		dataEvent.Msg[:dataEvent.MsgSize],
	)
}

func parseProto(event *bpf.MsgEvent, parser protocols.Parser) {
	if event.FlowType == bpf.REQUEST {
		req, err := parser.ParseRequest(event.Msg[:event.MsgSize])
		if err != nil {
			return
		}

		log.Printf("%s  %-10s\n %s\n\n",
			event.SockKey.String(),
			event.FlowType.String(),
			req.String(),
		)
	} else if event.FlowType == bpf.RESPONSE {
		resp, err := parser.ParseResponse(event.Msg[:event.MsgSize])
		if err != nil {
			return
		}

		log.Printf("%s  %-10s\n %s\n\n",
			event.SockKey.String(),
			event.FlowType.String(),
			resp.String(),
		)
	}
}
