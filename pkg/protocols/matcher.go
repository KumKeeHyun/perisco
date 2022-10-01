package protocols

import (
	"context"

	pb "github.com/KumKeeHyun/perisco/api/v1/perisco"
	"github.com/KumKeeHyun/perisco/pkg/ebpf/types"
	"go.uber.org/zap"
)

type reqRespMatcher struct {
	matchers       map[types.EndpointKey]ProtoMatcher
	protoMatcherOf func(types.ProtocolType) ProtoMatcher

	msgc chan *pb.ProtoMessage

	ctx    context.Context
	cancel context.CancelFunc
	donec  chan struct{}

	log *zap.SugaredLogger
}

func NewMatcher(protoMatcherOf func(types.ProtocolType) ProtoMatcher, log *zap.SugaredLogger) *reqRespMatcher {
	return &reqRespMatcher{
		matchers:       make(map[types.EndpointKey]ProtoMatcher),
		protoMatcherOf: protoMatcherOf,
		log:            log,
	}
}

func (rrm *reqRespMatcher) Run(ctx context.Context, reqc chan *Request, respc chan *Response) chan *pb.ProtoMessage {
	rrm.msgc = make(chan *pb.ProtoMessage, 100)

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
				rrm.tryMatchRequest(req)
			case resp := <-respc:
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
		rrm.log.Infof("new proto matcher of %s for %s", req.Record.ProtoType(), ep.String())
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
		rrm.log.Infof("new proto matcher of %s for %s", resp.Record.ProtoType(), ep.String())
	}

	if msg := m.MatchResponse(resp); msg != nil {
		rrm.msgc <- msg
	}
}
