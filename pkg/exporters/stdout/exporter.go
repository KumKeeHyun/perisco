package stdout

import (
	"context"
	"encoding/json"
	"errors"
	"os"

	pb "github.com/KumKeeHyun/perisco/api/v1/perisco"
)

type Exporter struct {
	encoder json.Encoder

	ctx    context.Context
	cancel context.CancelFunc
	donec  chan struct{}
}

func New() *Exporter {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")

	return &Exporter{
		encoder: *encoder,
	}
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
