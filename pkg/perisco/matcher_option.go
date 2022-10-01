package perisco

import (
	"fmt"

	"github.com/KumKeeHyun/perisco/pkg/ebpf/types"
	"github.com/KumKeeHyun/perisco/pkg/logger"
	"github.com/KumKeeHyun/perisco/pkg/perisco/protocols"
	"github.com/KumKeeHyun/perisco/pkg/perisco/protocols/http1"
	"github.com/KumKeeHyun/perisco/pkg/perisco/protocols/http2"
	"go.uber.org/zap"
)

type matcherOptions struct {
	protoMatcherOf func(types.ProtocolType) protocols.ProtoMatcher
	log            *zap.SugaredLogger
}

var defaultMatcherOptions = matcherOptions{
	protoMatcherOf: func(pt types.ProtocolType) protocols.ProtoMatcher { return nil },
	log:            logger.DefualtLogger,
}

type MatcherOption func(o *matcherOptions) error

func newMatcherOptions(opts ...MatcherOption) (*matcherOptions, error) {
	options := defaultMatcherOptions
	for _, opt := range opts {
		if err := opt(&options); err != nil {
			return nil, fmt.Errorf("failed to apply option: %v", err)
		}
	}
	return &options, nil
}

func MatcherWithProtocols(protos []types.ProtocolType) MatcherOption {
	table := make(map[types.ProtocolType]struct{})
	for _, proto := range protos {
		if proto != types.PROTO_UNKNOWN {
			table[proto] = struct{}{}
		}
	}
	return func(o *matcherOptions) error {
		o.protoMatcherOf = func(proto types.ProtocolType) protocols.ProtoMatcher {
			if _, exists := table[proto]; exists {
				return protoMatcherOf(proto)
			}
			return nil
		}
		return nil
	}
}

func protoMatcherOf(pt types.ProtocolType) protocols.ProtoMatcher {
	switch pt {
	case types.HTTP1:
		return http1.NewHTTP1Matcher()
	case types.HTTP2:
		return http2.NewHTTP2Matcher()
	default:
		return nil
	}
}

func MatcherWithLogger(log *zap.SugaredLogger) MatcherOption {
	return func(o *matcherOptions) error {
		o.log = log
		return nil
	}
}
