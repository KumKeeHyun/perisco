package perisco

import (
	"context"

	pb "github.com/KumKeeHyun/perisco/api/v1/perisco"
	"go.uber.org/zap"
)

type ResourceStore interface {
	FindEndpoint(ip string) *pb.Endpoint
	FindService(ip string) *pb.Service
}

type Enricher struct {

	msgc chan *pb.ProtoMessageInK8S

	ctx    context.Context
	cancel context.CancelFunc
	donec  chan struct{}

	log *zap.SugaredLogger
}

func NewEnricher(options ...EnricherOption) (*Enricher, error) {
	opts, err := newEnricherOptions(options...)
	if err != nil {
		return nil, err
	}

	return &Enricher{
		log: opts.log,
	}, nil
}

func (e *Enricher) Run(ctx context.Context, msgc chan *pb.ProtoMessage) chan *pb.ProtoMessageInK8S {
	e.msgc = make(chan *pb.ProtoMessageInK8S, 100)

	e.ctx, e.cancel = context.WithCancel(ctx)
	e.donec = make(chan struct{})
	go func() {
		defer func() {
			close(e.msgc)
			close(e.donec)
		}()

		for {
			select {
			case msg := <-msgc:
				e.enrichProtoMessage(msg)
			case <-e.ctx.Done():
				return
			}
		}
	}()

	return e.msgc
}

func (e *Enricher) enrichProtoMessage(msg *pb.ProtoMessage) {
	// TODO
	e.msgc <- &pb.ProtoMessageInK8S{
		Ts: msg.Ts,
		Pid: msg.Pid,
		Ip: msg.Ip,
		L4: msg.L4,
		L7: msg.L7,
	}
}