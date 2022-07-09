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
	h2Parser := protocols.NewHTTP2Parser()

	go func() {
		for {
			select {
			case dataEvent := <-recvCh:
				// rawLogging(dataEvent)
				parseH1Req(dataEvent, h1Parser)
				parseH2Req(dataEvent, h2Parser)
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
				parseH2Resp(dataEvent, h2Parser)
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
	req, err := parser.ParseRequest(msg)
	if err != nil {
		return
	}

	h1Req := req[0].(*protocols.HTTP1RequestHeader)
	log.Printf("%s\n", h1Req.String())
}


func parseH1Resp(msg *bpf.MsgEvent, parser *protocols.HTTP1Parser) {
	resp, err := parser.ParseResponse(msg)
	if err != nil {
		return
	}

	h1Resp := resp[0].(*protocols.HTTP1ResponseHeader)
	log.Printf("%s\n", h1Resp.String())
}

func parseH2Req(msg *bpf.MsgEvent, parser *protocols.HTTP2Parser) {
	reqs, err := parser.ParseRequest(msg)
	if err != nil {
		return
	}

	for _, req := range reqs {
		log.Printf("%s\n", req.(*protocols.HTTP2RequestHeader).String())
	}
}

func parseH2Resp(msg *bpf.MsgEvent, parser *protocols.HTTP2Parser) {
	resps, err := parser.ParseResponse(msg)
	if err != nil {
		return
	}

	for _, resp := range resps {
		log.Printf("%s\n", resp.(*protocols.HTTP2ResponseHeader).String())
	}
}