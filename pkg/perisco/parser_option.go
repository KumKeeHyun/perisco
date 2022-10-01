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

type parserOptions struct {
	parsers []protocols.ProtoParser
	breaker Breaker
	log     *zap.SugaredLogger
}

var defaultParserOptions = parserOptions{
	parsers: []protocols.ProtoParser{},
	breaker: &mockBreaker{},
	log:     logger.DefualtLogger,
}

type ParserOption func(o *parserOptions) error

func newParserOptions(opts ...ParserOption) (*parserOptions, error) {
	options := defaultParserOptions
	for _, opt := range opts {
		if err := opt(&options); err != nil {
			return nil, fmt.Errorf("failed to apply option: %v", err)
		}
	}
	return &options, nil
}

func ParserWithProtocols(protos []types.ProtocolType) ParserOption {
	parsers := make([]protocols.ProtoParser, 0, len(protos))
	for _, proto := range protos {
		if parser := protoParserOf(proto); parser != nil {
			parsers = append(parsers, parser)
		}
	}
	return func(o *parserOptions) error {
		o.parsers = parsers
		return nil
	}
}

func protoParserOf(pt types.ProtocolType) protocols.ProtoParser {
	switch pt {
	case types.HTTP1:
		return http1.NewHTTP1Parser()
	case types.HTTP2:
		return http2.NewHTTP2Parser()
	default:
		return nil
	}
}

func ParserWithBreaker(breaker Breaker) ParserOption {
	return func(o *parserOptions) error {
		o.breaker = breaker
		return nil
	}
}

func ParserWithLogger(log *zap.SugaredLogger) ParserOption {
	return func(o *parserOptions) error {
		o.log = log
		return nil
	}
}
