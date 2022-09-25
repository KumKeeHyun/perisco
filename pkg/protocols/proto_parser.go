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
	RequestRecord() *pb.Request
	String() string
}

type ProtoResponse interface {
	ProtoType() types.ProtocolType
	ResponseRecord() *pb.Response
	String() string
}

type ProtoParser interface {
	ProtoType() types.ProtocolType
	ParseRequest(sockKey *types.SockKey, msg []byte) ([]ProtoRequest, error)
	ParseResponse(sockKey *types.SockKey, msg []byte) ([]ProtoResponse, error)
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
		if rr, err := p.ParseRequest(sockKey, msg); err == nil {
			return rr, nil
		}
	}
	return nil, ErrUnknownProtocolMsg
}

// ParseResponse implements ProtoParser
func (up *UnknownParser) ParseResponse(sockKey *types.SockKey, msg []byte) ([]ProtoResponse, error) {
	for _, p := range up.parsers {
		if rr, err := p.ParseResponse(sockKey, msg); err == nil {
			return rr, nil
		}
	}
	return nil, ErrUnknownProtocolMsg
}
