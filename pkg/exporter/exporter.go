package exporters

import (
	"context"

	pb "github.com/KumKeeHyun/perisco/api/v1/perisco"
)

type Exporter interface {
	Export(ctx context.Context, msgc chan *pb.ProtoMessage)
	ExportK8S(ctx context.Context, msgc chan *pb.K8SProtoMessage)
	Stop() error
}

func New() Exporter {
	return nil
}
