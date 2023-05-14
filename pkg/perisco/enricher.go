package perisco

import (
	"context"
	"errors"

	pb "github.com/KumKeeHyun/perisco/api/v1/perisco"
	"go.uber.org/zap"
)

type ResourcesStore interface {
	GetPodInfo(ip string) *pb.Endpoint
	GetServiceInfo(ip string) *pb.Service
}

type Enricher struct {
	store ResourcesStore
	msgc  chan *pb.K8SProtoMessage

	ctx    context.Context
	cancel context.CancelFunc
	donec  chan struct{}

	log *zap.SugaredLogger
}

func NewEnricher(log *zap.SugaredLogger, store ResourcesStore) (*Enricher, error) {
	return &Enricher{
		store: store,
		log:   log,
	}, nil
}

func (e *Enricher) Run(ctx context.Context, msgc chan *pb.ProtoMessage) chan *pb.K8SProtoMessage {
	e.msgc = make(chan *pb.K8SProtoMessage, 100)

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
	e.msgc <- &pb.K8SProtoMessage{
		ProtoMessage_: msg,
		Client:        e.store.GetPodInfo(msg.Ip.Client),
		Server:        e.store.GetPodInfo(msg.Ip.Server),
		ClientService: e.store.GetServiceInfo(msg.Ip.Client),
		ServerService: e.store.GetServiceInfo(msg.Ip.Server),
	}
}

func (e *Enricher) Stop() error {
	if e.cancel != nil {
		e.cancel()
	}
	<-e.donec
	e.log.Info("enricher stopped")

	err := e.ctx.Err()
	if !errors.Is(err, context.Canceled) {
		return err
	}
	return nil
}
