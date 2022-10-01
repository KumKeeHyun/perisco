package stdout

import (
	"context"
	"encoding/json"
	"errors"

	pb "github.com/KumKeeHyun/perisco/api/v1/perisco"
)

type Exporter struct {
	encoder json.Encoder

	ctx    context.Context
	cancel context.CancelFunc
	donec  chan struct{}
}

func New(options ...Option) (*Exporter, error) {
	opts, err := newOptions(options...)
	if err != nil {
		return nil, err
	}

	encoder := json.NewEncoder(opts.Writer)
	if opts.Pretty {
		encoder.SetIndent("", "  ")
	}

	return &Exporter{
		encoder: *encoder,
	}, nil
}

func (e *Exporter) Export(ctx context.Context, msgc chan *pb.ProtoMessage) {
	e.ctx, e.cancel = context.WithCancel(ctx)
	e.donec = make(chan struct{})

	defer close(e.donec)

	for {
		select {
		case msg := <-msgc:
			e.encoder.Encode(msg)
		case <-e.ctx.Done():
			return
		}
	}
}

func (e *Exporter) Shutdown() error {
	if e.cancel != nil {
		e.cancel()
	}
	<-e.donec

	err := e.ctx.Err()
	if !errors.Is(err, context.Canceled) {
		return err
	}
	return nil
}
