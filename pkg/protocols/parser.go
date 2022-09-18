package protocols

import (
	"context"
	"errors"
	"fmt"

	"github.com/KumKeeHyun/perisco/pkg/ebpf/maps"
	"github.com/KumKeeHyun/perisco/pkg/ebpf/types"
	"go.uber.org/zap"
)

type Request struct {
	SockKey   types.SockKey
	Timestamp uint64

	Record RequestRecord
}

func (r *Request) String() string {
	return fmt.Sprintf("%s\n%s\n", r.SockKey.String(), r.Record.String())
}

type Response struct {
	SockKey   types.SockKey
	Timestamp uint64
	Record    ResponseRecord
}

func (r *Response) String() string {
	return fmt.Sprintf("%s\n%s\n", r.SockKey.String(), r.Record.String())
}

type reqRespParser struct {
	parsers map[types.ProtocolType]ProtoParser
	breaker Breaker

	reqc  chan *Request
	respc chan *Response

	ctx    context.Context
	cancel context.CancelFunc
	donec  chan struct{}

	log *zap.SugaredLogger
}

func NewParser(parsers []ProtoParser, pm *maps.ProtocolMap, log *zap.SugaredLogger) *reqRespParser {
	pps := make(map[types.ProtocolType]ProtoParser, len(parsers)+1)
	for _, p := range parsers {
		pps[p.ProtoType()] = p
	}
	pps[types.PROTO_UNKNOWN] = NewUnknownParser(parsers)

	var breaker Breaker
	if pm == nil {
		breaker = &mockBreaker{}
	} else {
		breaker = NewProtoDetecter(pm, log.Named("protoDetecter"))
	}

	return &reqRespParser{
		parsers: pps,
		breaker: breaker,
		log:     log,
	}
}

func (rrp *reqRespParser) Run(ctx context.Context, recvc, sendc chan *types.MsgEvent) (chan *Request, chan *Response) {
	rrp.reqc = make(chan *Request, 100)
	rrp.respc = make(chan *Response, 100)

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
		rrp.reqc <- &Request{
			SockKey:   msg.SockKey,
			Timestamp: msg.Timestamp,
			Record:    rr,
		}
	}
}

func (rrp *reqRespParser) findParser(msg *types.MsgEvent) ProtoParser {
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
		rrp.respc <- &Response{
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
