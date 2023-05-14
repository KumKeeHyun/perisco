package file

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"

	pb "github.com/KumKeeHyun/perisco/api/v1/perisco"
	"google.golang.org/protobuf/encoding/protojson"
)

type FileConfig struct {
	Name   string `mapstructure:"EXPORTER_FILE_NAME"`
	Pretty bool   `mapstructure:"EXPORTER_FILE_PRETTY"`
}

type Exporter struct {
	w       io.WriteCloser
	encoder *protojson.MarshalOptions

	ctx    context.Context
	cancel context.CancelFunc
	donec  chan struct{}
}

func New(cfg FileConfig) (*Exporter, error) {
	var err error
	w := os.Stdout
	if cfg.Name != "" {
		w, err = os.OpenFile(cfg.Name, os.O_CREATE|os.O_APPEND|os.O_RDWR, 0644)
		if err != nil {
			return nil, fmt.Errorf("failed to create file exporter: %w", err)
		}
	}

	encoder := &protojson.MarshalOptions{}
	if cfg.Pretty {
		encoder.Indent = "  "
	}

	return &Exporter{
		w:       w,
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

	defer func() {
		e.w.Close()
		close(e.donec)
	}()

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

func (e *Exporter) Stop() error {
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
