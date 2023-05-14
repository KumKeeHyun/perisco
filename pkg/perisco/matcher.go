package perisco

import (
	"context"
	"errors"

	pb "github.com/KumKeeHyun/perisco/api/v1/perisco"
	"github.com/KumKeeHyun/perisco/pkg/ebpf/types"
	"github.com/KumKeeHyun/perisco/pkg/perisco/protocols"
	"go.uber.org/zap"
)

type reqRespMatcher struct {
	matchers       map[types.EndpointKey]protocols.ProtoMatcher
	protoMatcherOf func(types.ProtocolType) protocols.ProtoMatcher

	msgc chan *pb.ProtoMessage

	ctx    context.Context
	cancel context.CancelFunc
	donec  chan struct{}

	log *zap.SugaredLogger
}

func NewMatcher(options ...MatcherOption) (*reqRespMatcher, error) {
	opts, err := newMatcherOptions(options...)
	if err != nil {
		return nil, err
	}
	return &reqRespMatcher{
		matchers:       make(map[types.EndpointKey]protocols.ProtoMatcher),
		protoMatcherOf: opts.protoMatcherOf,
		log:            opts.log,
	}, nil
}

func (rrm *reqRespMatcher) Run(ctx context.Context, reqc chan *protocols.Request, respc chan *protocols.Response) chan *pb.ProtoMessage {
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

func (rrm *reqRespMatcher) tryMatchRequest(req *protocols.Request) {
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

func (rrm *reqRespMatcher) tryMatchResponse(resp *protocols.Response) {
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

func (rrm *reqRespMatcher) Stop() error {
	if rrm.cancel != nil {
		rrm.cancel()
	}
	<-rrm.donec
	rrm.log.Info("matcher stopped")

	err := rrm.ctx.Err()
	if !errors.Is(err, context.Canceled) {
		return err
	}
	return nil
}
