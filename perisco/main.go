package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/KumKeeHyun/perisco/perisco/bpf"
	"github.com/KumKeeHyun/perisco/perisco/config"
	"github.com/KumKeeHyun/perisco/pkg/ebpf/types"
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

	recvc, sendc, netFilterMap, clean := bpf.LoadBpfProgram()
	defer clean()

	nf := bpf.NewNetworkFilter(netFilterMap)
	defer nf.Close()

	if err := nf.Update(config.CidrSlice()); err != nil {
		log.Fatal(err)
	}
	log.Printf("network filter: %v", config.CidrSlice())

	reqc, respc := protocols.RunParser(ctx, recvc, sendc)
	go func () {
		for {
			select {
			case req := <-reqc:
				log.Println(req)
			case resp := <-respc:
				log.Println(resp)
			case <-ctx.Done():
				return
			}
		}
	}()

	/* parser := protocols.NewUnknownParser([]protocols.ProtoParser{
		protocols.NewHTTP1Parser(),
		protocols.NewHTTP2Parser(),
	})

	go func() {
		for {
			select {
			case msgEvent := <-recvCh:
				// rawLogging(dataEvent)
				if req, err := parser.ParseRequest(&msgEvent.SockKey, msgEvent.Bytes()); err == nil {
					log.Printf("%s\n%s\n", msgEvent.SockKey.String(), req.String())
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	go func() {
		for {
			select {
			case msgEvent := <-sendCh:
				if resp, err := parser.ParseRequest(&msgEvent.SockKey, msgEvent.Bytes()); err == nil {
					log.Printf("%s\n%s\n", msgEvent.SockKey.String(), resp.String())
				}
			case <-ctx.Done():
				return
			}
		}
	}() */

	<-ctx.Done()
}

func rawLogging(dataEvent *types.MsgEvent) {
	log.Printf("%s  %-10s\nsize: %d, msg: %s\n",
		dataEvent.SockKey.String(),
		dataEvent.FlowType.String(),
		dataEvent.MsgSize,
		dataEvent.Msg[:dataEvent.MsgSize],
	)
}
