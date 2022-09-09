package protocols

import (
	"errors"

	"github.com/KumKeeHyun/perisco/pkg/ebpf/types"
)

var (
	ErrNotExistsHeader    = errors.New("protocols: not exists header")
	ErrUnknownProtocolMsg = errors.New("protocols: unknown protocol msg")
)

type RequestRecord interface {
	ProtoType() types.ProtocolType
	RequestRecord()
	String() string
}

type ResponseRecord interface {
	ProtoType() types.ProtocolType
	ResponseRecord()
	String() string
}

type ProtoParser interface {
	ProtoType() types.ProtocolType
	ParseRequest(sockKey *types.SockKey, msg []byte) ([]RequestRecord, error)
	ParseResponse(sockKey *types.SockKey, msg []byte) ([]ResponseRecord, error)
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
func (up *UnknownParser) ParseRequest(sockKey *types.SockKey, msg []byte) ([]RequestRecord, error) {
	for _, p := range up.parsers {
		if rr, err := p.ParseRequest(sockKey, msg); err == nil {
			return rr, nil
		}
	}
	return nil, ErrUnknownProtocolMsg
}

// ParseResponse implements ProtoParser
func (up *UnknownParser) ParseResponse(sockKey *types.SockKey, msg []byte) ([]ResponseRecord, error) {
	for _, p := range up.parsers {
		if rr, err := p.ParseResponse(sockKey, msg); err == nil {
			return rr, nil
		}
	}
	return nil, ErrUnknownProtocolMsg
}
