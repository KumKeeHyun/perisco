package perisco

import (
	"fmt"

	"github.com/KumKeeHyun/perisco/pkg/logger"
	"go.uber.org/zap"
)

type enricherOptions struct {
	log *zap.SugaredLogger
}

var defaultEnricherOptions = enricherOptions{
	log: logger.DefualtLogger,
}

type EnricherOption func(o *enricherOptions) error

func newEnricherOptions(opts ...EnricherOption) (*enricherOptions, error) {
	options := defaultEnricherOptions
	for _, opt := range opts {
		if err := opt(&options); err != nil {
			return nil, fmt.Errorf("failed to apply option: %v", err)
		}
	}
	return &options, nil
}

func EnricherWithLogger(log *zap.SugaredLogger) EnricherOption {
	return func(o *enricherOptions) error {
		o.log = log
		return nil
	}
}