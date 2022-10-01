package perisco

import (
	"context"
	"errors"

	"github.com/KumKeeHyun/perisco/pkg/ebpf/types"
	"github.com/KumKeeHyun/perisco/pkg/perisco/protocols"
	"go.uber.org/zap"
)

type reqRespParser struct {
	parsers map[types.ProtocolType]protocols.ProtoParser
	breaker Breaker

	reqc  chan *protocols.Request
	respc chan *protocols.Response

	ctx    context.Context
	cancel context.CancelFunc
	donec  chan struct{}

	log *zap.SugaredLogger
}

func NewParser(parsers []protocols.ProtoParser, breaker Breaker, log *zap.SugaredLogger) *reqRespParser {
	pps := make(map[types.ProtocolType]protocols.ProtoParser, len(parsers)+1)
	for _, p := range parsers {
		pps[p.ProtoType()] = p
	}
	pps[types.PROTO_UNKNOWN] = protocols.NewUnknownParser(parsers)

	if breaker == nil {
		breaker = &mockBreaker{}
	}

	return &reqRespParser{
		parsers: pps,
		breaker: breaker,
		log:     log,
	}
}

func (rrp *reqRespParser) Run(ctx context.Context, recvc, sendc chan *types.MsgEvent) (chan *protocols.Request, chan *protocols.Response) {
	rrp.reqc = make(chan *protocols.Request, 100)
	rrp.respc = make(chan *protocols.Response, 100)

	rrp.ctx, rrp.cancel = context.WithCancel(ctx)
	rrp.donec = make(chan struct{})
	go func() {
		defer func() {
			close(rrp.reqc)
			close(rrp.respc)
			close(rrp.donec)
		}()

		for {
			select {
			case msg := <-recvc:
				rrp.tryParseRequest(msg)
			case msg := <-sendc:
				rrp.tryParseResponse(msg)
			case <-rrp.ctx.Done():
				return
			}
		}
	}()

	return rrp.reqc, rrp.respc
}

func (rrp *reqRespParser) tryParseRequest(msg *types.MsgEvent) {
	p := rrp.findParser(msg)
	rrs, err := p.ParseRequest(&msg.SockKey, msg.Bytes())
	if err != nil {
		rrp.breaker.Fail(msg.SockKey)
		return
	}

	rrp.breaker.Success(msg.SockKey, rrs[0].ProtoType())

	for _, rr := range rrs {
		rrp.reqc <- &protocols.Request{
			SockKey:   msg.SockKey,
			Timestamp: msg.Timestamp,
			Record:    rr,
		}
	}
}

func (rrp *reqRespParser) findParser(msg *types.MsgEvent) protocols.ProtoParser {
	if p, exists := rrp.parsers[msg.Protocol]; exists {
		return p
	}
	return nil
}

func (rrp *reqRespParser) tryParseResponse(msg *types.MsgEvent) {
	p := rrp.findParser(msg)
	if p == nil {
		return
	}

	rrs, err := p.ParseResponse(&msg.SockKey, msg.Bytes())
	if err != nil {
		rrp.breaker.Fail(msg.SockKey)
		return
	}

	rrp.breaker.Success(msg.SockKey, rrs[0].ProtoType())
	for _, rr := range rrs {
		rrp.respc <- &protocols.Response{
			SockKey:   msg.SockKey,
			Timestamp: msg.Timestamp,
			Record:    rr,
		}
	}

}

func (rrp *reqRespParser) Close() error {
	if rrp.cancel != nil {
		rrp.cancel()
	}
	<-rrp.donec

	err := rrp.ctx.Err()
	if !errors.Is(err, context.Canceled) {
		return err
	}
	return nil
}
