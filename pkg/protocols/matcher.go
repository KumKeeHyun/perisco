package protocols

import (
	"context"
	"log"

	"github.com/KumKeeHyun/perisco/pkg/ebpf/types"
	"go.uber.org/zap"
)

type reqRespMatcher struct {
	matchers     map[types.EndpointKey]ProtoMatcher
	protoMatcherOf func(types.ProtocolType) ProtoMatcher

	msgc chan *ProtoMessage

	ctx    context.Context
	cancel context.CancelFunc
	donec  chan struct{}

	log *zap.SugaredLogger
}

func NewMatcher(protoMatcherOf func(types.ProtocolType) ProtoMatcher, log *zap.SugaredLogger) *reqRespMatcher {
	return &reqRespMatcher{
		matchers:     make(map[types.EndpointKey]ProtoMatcher),
		protoMatcherOf: protoMatcherOf,
		log: log,
	}
}

func (rrm *reqRespMatcher) Run(ctx context.Context, reqc chan *Request, respc chan *Response) chan *ProtoMessage {
	rrm.msgc = make(chan *ProtoMessage, 100)

	rrm.ctx, rrm.cancel = context.WithCancel(ctx)
	rrm.donec = make(chan struct{})
	go func() {
		defer func() {
			close(rrm.msgc)
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

	return rrm.msgc
}

func (rrm *reqRespMatcher) tryMatchRequest(req *Request) {
	ep := req.SockKey.ToServerEndpoint()
	m, exists := rrm.matchers[ep]
	if !exists {
		if m = rrm.protoMatcherOf(req.Record.ProtoType()); m == nil {
			return
		}
		rrm.matchers[ep] = m
		log.Printf("new proto matcher of %s for %s", req.Record.ProtoType(), ep.String())
	}

	if msg := m.MatchRequest(req); msg != nil {
		rrm.msgc <- msg
	}
}

func (rrm *reqRespMatcher) tryMatchResponse(resp *Response) {
	ep := resp.SockKey.ToServerEndpoint()
	m, exists := rrm.matchers[ep]
	if !exists {
		if m = rrm.protoMatcherOf(resp.Record.ProtoType()); m == nil {
			return
		}
		rrm.matchers[ep] = m
		log.Printf("new proto matcher of %s for %s", resp.Record.ProtoType(), ep.String())
	}

	if msg := m.MatchResponse(resp); msg != nil {
		rrm.msgc <- msg
	}
}
