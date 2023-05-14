package exporter

import (
	"context"

	pb "github.com/KumKeeHyun/perisco/api/v1/perisco"
	"github.com/KumKeeHyun/perisco/pkg/exporter/elasticsearch"
	"github.com/KumKeeHyun/perisco/pkg/exporter/file"
)

type Config struct {
	Exporter string `mapstructure:"EXPORTER"`

	file.FileConfig        `mapstructure:",squash"`
	elasticsearch.ESConfig `mapstructure:",squash"`
}

type Exporter interface {
	Export(ctx context.Context, msgc chan *pb.ProtoMessage)
	ExportK8S(ctx context.Context, msgc chan *pb.K8SProtoMessage)
	Stop() error
}

func New(cfg Config) Exporter {

	return nil
}
