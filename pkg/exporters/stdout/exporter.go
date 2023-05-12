package stdout

import (
	"context"
	"errors"
	"io"

	pb "github.com/KumKeeHyun/perisco/api/v1/perisco"
	"google.golang.org/protobuf/encoding/protojson"
)

type Exporter struct {
	w       io.Writer
	encoder *protojson.MarshalOptions

	ctx    context.Context
	cancel context.CancelFunc
	donec  chan struct{}
}

func New(options ...Option) (*Exporter, error) {
	opts, err := newOptions(options...)
	if err != nil {
		return nil, err
	}

	encoder := &protojson.MarshalOptions{}
	if opts.Pretty {
		encoder.Indent = "  "
	}

	return &Exporter{
		w:       opts.Writer,
		encoder: encoder,
	}, nil
}

func (e *Exporter) Export(ctx context.Context, msgc chan *pb.ProtoMessage) {
	e.ctx, e.cancel = context.WithCancel(ctx)
	e.donec = make(chan struct{})

	defer close(e.donec)

	for {
		select {
		case msg := <-msgc:
			if b, err := e.encoder.Marshal(msg); err == nil {
				e.w.Write(b)
				e.w.Write([]byte("\n"))
			}
		case <-e.ctx.Done():
			return
		}
	}
}

func (e *Exporter) ExportK8S(ctx context.Context, msgc chan *pb.K8SProtoMessage) {
	e.ctx, e.cancel = context.WithCancel(ctx)
	e.donec = make(chan struct{})

	defer close(e.donec)

	for {
		select {
		case msg := <-msgc:
			if b, err := e.encoder.Marshal(msg); err == nil {
				e.w.Write(b)
				e.w.Write([]byte("\n"))
			}
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
