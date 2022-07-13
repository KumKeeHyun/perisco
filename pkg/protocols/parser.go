package protocols

import (
	"context"

	"github.com/KumKeeHyun/perisco/pkg/ebpf/types"
)

type Request struct {
	// some headers...
	Record RequestRecord
}

type Response struct {
	// some headers...
	Record ResponseRecord
}

type ReqRespParser struct {
	parsers map[types.ProtocolType]ProtoParser
	breaker Breaker

	reqc  chan *Request
	respc chan *Response
}

func newReqRespParser(parsers []ProtoParser, breaker Breaker) *ReqRespParser {
	parser := &ReqRespParser{
		parsers: make(map[types.ProtocolType]ProtoParser, len(parsers)+1),
		breaker: breaker,
	}

	for _, p := range parsers {
		parser.parsers[p.GetProtoType()] = p
	}
	parser.parsers[types.PROTO_UNKNOWN] = NewUnknownParser(parsers)

	return parser
}

func (rrp *ReqRespParser) run(ctx context.Context, recv, sendc chan *types.MsgEvent) (chan *Request, chan *Response) {
	reqc := make(chan *Request, 100)
	respc := make(chan *Response, 100)

	rrp.reqc = reqc
	rrp.respc = respc

	go func() {
		defer func() {
			close(reqc)
			close(respc)
		}()

		for {
			select {
			case rme := <-recv:
				rrp.tryParseRequest(rme)
			case sme := <-sendc:
				rrp.tryParseResponse(sme)
			case <-ctx.Done():
				return
			}
		}
	}()

	return reqc, respc
}

func (rrp *ReqRespParser) tryParseRequest(me *types.MsgEvent) {
	p := rrp.findParser(me)
	rr, err := p.ParseRequest(&me.SockKey, me.Bytes())
	if err != nil {
		rrp.breaker.Fail(me.SockKey)
		return
	}

	rrp.breaker.Success(me.SockKey, p.GetProtoType())
	rrp.reqc <- &Request{
		Record: rr,
	}
}

func (rrp *ReqRespParser) findParser(me *types.MsgEvent) ProtoParser {
	if p, exists := rrp.parsers[me.Protocol]; exists {
		return p
	}
	return rrp.parsers[types.PROTO_UNKNOWN]
}

func (rrp *ReqRespParser) tryParseResponse(me *types.MsgEvent) {
	p := rrp.findParser(me)
	rr, err := p.ParseResponse(&me.SockKey, me.Bytes())
	if err != nil {
		rrp.breaker.Fail(me.SockKey)
		return
	}

	rrp.breaker.Success(me.SockKey, p.GetProtoType())
	rrp.respc <- &Response{
		Record: rr,
	}
}
