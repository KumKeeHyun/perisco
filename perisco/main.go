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

	h1Parser := protocols.NewHTTP1Parser()
	// h2Parser := protocols.NewHTTP2Parser()

	go func() {
		for {
			select {
			case dataEvent := <-recvCh:
				// rawLogging(dataEvent)
				parseH1Req(dataEvent, h1Parser)
				// parseH2Req(dataEvent, h2Parser)
			case <-ctx.Done():
				return
			}
		}
	}()

	go func() {
		for {
			select {
			case dataEvent := <-sendCh:
				// rawLogging(dataEvent)
				parseH1Resp(dataEvent, h1Parser)
				// parseH2Resp(dataEvent, h2Parser)
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

func parseH1Req(msg *bpf.MsgEvent, parser *protocols.HTTP1Parser) {
	req, err := parser.ParseRequest(nil, msg.GetBytes())
	if err != nil {
		return
	}

	log.Printf("%s\n%s\n", msg.SockKey.String(), req.String())
}

func parseH1Resp(msg *bpf.MsgEvent, parser *protocols.HTTP1Parser) {
	resp, err := parser.ParseResponse(nil, msg.GetBytes())
	if err != nil {
		return
	}

	log.Printf("%s\n%s\n", msg.SockKey.String(), resp.String())
}

func parseH2Req(msg *bpf.MsgEvent, parser *protocols.HTTP2Parser) {
	req, err := parser.ParseRequest(&msg.SockKey, msg.GetBytes())
	if err != nil {
		return
	}

	log.Printf("%s\n%s\n", msg.SockKey.String(), req.String())
}

func parseH2Resp(msg *bpf.MsgEvent, parser *protocols.HTTP2Parser) {
	resp, err := parser.ParseResponse(&msg.SockKey, msg.GetBytes())
	if err != nil {
		return
	}

	log.Printf("%s\n%s\n", msg.SockKey.String(), resp.String())
}
