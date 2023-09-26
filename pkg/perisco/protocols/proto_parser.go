package protocols

import (
	"errors"

	"github.com/KumKeeHyun/perisco/pkg/ebpf/types"

	pb "github.com/KumKeeHyun/perisco/api/v1/perisco"
)

var (
	ErrNotExistsHeader    = errors.New("protocols: not exists header")
	ErrUnknownProtocolMsg = errors.New("protocols: unknown protocol msg")
)

type ProtoRequest interface {
	ProtoType() types.ProtocolType
	Protobuf() *pb.Request
}

type ProtoResponse interface {
	ProtoType() types.ProtocolType
	Protobuf() *pb.Response
}

type ProtoParser interface {
	ProtoType() types.ProtocolType
	ParseRequest(sockKey *types.SockKey, msg []byte) ([]ProtoRequest, error)
	EnableInferRequest() bool
	ParseResponse(sockKey *types.SockKey, msg []byte) ([]ProtoResponse, error)
	EnableInferResponse() bool
}

type UnknownParser struct {
	parsers []ProtoParser
}

var _ ProtoParser = &UnknownParser{}

func NewUnknownParser(parsers []ProtoParser) *UnknownParser {
	return &UnknownParser{
		parsers: parsers,
	}
}

// GetProtoType implements ProtoParser
func (*UnknownParser) ProtoType() types.ProtocolType { return types.PROTO_UNKNOWN }

// ParseRequest implements ProtoParser
func (up *UnknownParser) ParseRequest(sockKey *types.SockKey, msg []byte) ([]ProtoRequest, error) {
	for _, p := range up.parsers {
		if !p.EnableInferRequest() {
			continue
		}
		if rr, err := p.ParseRequest(sockKey, msg); err == nil {
			return rr, nil
		}
	}
	return nil, ErrUnknownProtocolMsg
}

func (up *UnknownParser) EnableInferRequest() bool {
	return true
}

// ParseResponse implements ProtoParser
func (up *UnknownParser) ParseResponse(sockKey *types.SockKey, msg []byte) ([]ProtoResponse, error) {
	for _, p := range up.parsers {
		if !p.EnableInferResponse() {
			continue
		}
		if rr, err := p.ParseResponse(sockKey, msg); err == nil {
			return rr, nil
		}
	}
	return nil, ErrUnknownProtocolMsg
}

func (up *UnknownParser) EnableInferResponse() bool {
	return true
}
