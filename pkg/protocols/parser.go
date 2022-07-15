package protocols

import (
	"context"
	"errors"
	"fmt"

	"github.com/KumKeeHyun/perisco/pkg/ebpf/types"
)

type Request struct {
	SockKey types.SockKey
	Record  RequestRecord
}

func (r *Request) String() string {
	return fmt.Sprintf("%s\n%s\n", r.SockKey.String(), r.Record.String())
}

type Response struct {
	SockKey types.SockKey
	Record  ResponseRecord
}


func (r *Response) String() string {
	return fmt.Sprintf("%s\n%s\n", r.SockKey.String(), r.Record.String())
}

type ReqRespParser struct {
	parsers map[types.ProtocolType]ProtoParser
	breaker Breaker

	reqc  chan *Request
	respc chan *Response

	ctx    context.Context
	cancel context.CancelFunc
	donec  chan struct{}
}

func RunParser(ctx context.Context, recvc, sendc chan *types.MsgEvent) (chan *Request, chan *Response) {
	parsers := []ProtoParser{
		NewHTTP1Parser(),
		NewHTTP2Parser(),
	}
	rrp := newReqRespParser(parsers, &mockBreaker{})
	return rrp.run(ctx, recvc, sendc)
}

func newReqRespParser(parsers []ProtoParser, breaker Breaker) *ReqRespParser {
	parser := &ReqRespParser{
		parsers: make(map[types.ProtocolType]ProtoParser, len(parsers)+1),
		breaker: breaker,
		donec:   make(chan struct{}),
	}

	for _, p := range parsers {
		parser.parsers[p.ProtoType()] = p
	}
	parser.parsers[types.PROTO_UNKNOWN] = NewUnknownParser(parsers)

	return parser
}

func (rrp *ReqRespParser) run(ctx context.Context, recvc, sendc chan *types.MsgEvent) (chan *Request, chan *Response) {
	reqc := make(chan *Request, 100)
	respc := make(chan *Response, 100)

	rrp.reqc = reqc
	rrp.respc = respc

	rrp.ctx, rrp.cancel = context.WithCancel(ctx)
	go func() {
		defer func() {
			close(reqc)
			close(respc)
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

	return reqc, respc
}

func (rrp *ReqRespParser) tryParseRequest(msg *types.MsgEvent) {
	p := rrp.findParser(msg)
	rr, err := p.ParseRequest(&msg.SockKey, msg.Bytes())
	if err != nil {
		rrp.breaker.Fail(msg.SockKey)
		return
	}

	rrp.breaker.Success(msg.SockKey, p.ProtoType())
	rrp.reqc <- &Request{
		SockKey: msg.SockKey,
		Record:  rr,
	}
}

func (rrp *ReqRespParser) findParser(msg *types.MsgEvent) ProtoParser {
	if p, exists := rrp.parsers[msg.Protocol]; exists {
		return p
	}
	return nil
}

func (rrp *ReqRespParser) tryParseResponse(msg *types.MsgEvent) {
	p := rrp.findParser(msg)
	if p == nil {
		return
	}

	rr, err := p.ParseResponse(&msg.SockKey, msg.Bytes())
	if err != nil {
		rrp.breaker.Fail(msg.SockKey)
		return
	}

	rrp.breaker.Success(msg.SockKey, p.ProtoType())
	rrp.respc <- &Response{
		SockKey: msg.SockKey,
		Record:  rr,
	}
}

func (rrp *ReqRespParser) Close() error {
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
