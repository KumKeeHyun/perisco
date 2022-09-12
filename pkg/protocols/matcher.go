package protocols

import (
	"context"
	"log"

	"github.com/KumKeeHyun/perisco/pkg/ebpf/types"
)

type ReqRespMatcher struct {
	matchers map[types.EndpointKey]ProtoMatcher

	msgc chan *ProtoMessage

	ctx    context.Context
	cancel context.CancelFunc
	donec  chan struct{}
}

func RunMatcher(ctx context.Context, reqc chan *Request, respc chan *Response) chan *ProtoMessage {
	rrm := newReqRespMatcher()
	return rrm.run(ctx, reqc, respc)
}

func newReqRespMatcher() *ReqRespMatcher {
	return &ReqRespMatcher{
		matchers: make(map[types.EndpointKey]ProtoMatcher),
		donec:    make(chan struct{}),
	}
}

func (rrm *ReqRespMatcher) run(ctx context.Context, reqc chan *Request, respc chan *Response) chan *ProtoMessage {
	msgc := make(chan *ProtoMessage, 100)
	rrm.msgc = msgc

	rrm.ctx, rrm.cancel = context.WithCancel(ctx)
	go func() {
		defer func() {
			close(msgc)
			close(rrm.donec)
		}()

		for {
			select {
			case req := <-reqc:
				// log.Println(req)
				rrm.tryMatchRequest(req)
			case resp := <-respc:
				// log.Println(resp)
				rrm.tryMatchResponse(resp)
			case <-rrm.ctx.Done():
				return
			}
		}
	}()

	return msgc
}

func (rrm *ReqRespMatcher) tryMatchRequest(req *Request) {
	ep := req.SockKey.ToServerEndpoint()
	m, exists := rrm.matchers[ep]
	if !exists {
		if m = NewProtoMatcherOf(req.Record.ProtoType()); m == nil {
			return
		}
		rrm.matchers[ep] = m
		log.Printf("new proto matcher of %s for %s", req.Record.ProtoType(), ep.String())
	}

	if msg := m.MatchRequest(req); msg != nil {
		rrm.msgc <- msg
	}
}

func (rrm *ReqRespMatcher) tryMatchResponse(resp *Response) {
	ep := resp.SockKey.ToServerEndpoint()
	m, exists := rrm.matchers[ep]
	if !exists {
		if m = NewProtoMatcherOf(resp.Record.ProtoType()); m == nil {
			return
		}
		rrm.matchers[ep] = m
		log.Printf("new proto matcher of %s for %s", resp.Record.ProtoType(), ep.String())
	}

	if msg := m.MatchResponse(resp); msg != nil {
		rrm.msgc <- msg
	}
}
