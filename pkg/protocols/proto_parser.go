package protocols

import (
	"errors"

	"github.com/KumKeeHyun/perisco/perisco/bpf"
)

var (
	ErrNotExistsHeader = errors.New("protocols: not exists header")
	ErrUnknownProtocolMsg = errors.New("protocols: unknown protocol msg")
)

type RequestRecord interface {
	ProtoType() bpf.ProtocolType
	RequestRecord()
	String() string
}

type ResponseRecord interface {
	ProtoType() bpf.ProtocolType
	ResponseRecord()
	String() string
}

type ProtoParser interface {
	GetProtoType() bpf.ProtocolType
	ParseRequest(sockKey *bpf.SockKey, msg []byte) (RequestRecord, error)
	ParseResponse(sockKey *bpf.SockKey, msg []byte) (ResponseRecord, error)
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
func (*UnknownParser) GetProtoType() bpf.ProtocolType { return bpf.PROTO_UNKNOWN }

// ParseRequest implements ProtoParser
func (up *UnknownParser) ParseRequest(sockKey *bpf.SockKey, msg []byte) (RequestRecord, error) {
	for _, p := range up.parsers {
		if rr, err := p.ParseRequest(sockKey, msg); err == nil {
			return rr, nil
		}
	} 
	return nil, ErrUnknownProtocolMsg
}

// ParseResponse implements ProtoParser
func (up *UnknownParser) ParseResponse(sockKey *bpf.SockKey, msg []byte) (ResponseRecord, error) {
	for _, p := range up.parsers {
		if rr, err := p.ParseResponse(sockKey, msg); err == nil {
			return rr, nil
		}
	}
	return nil, ErrUnknownProtocolMsg
}


type ReqRespParser struct {
	parsers map[bpf.ProtocolType]ProtoParser
	breaker Breaker
}

func parseRequest(me *bpf.MsgEvent) {

}