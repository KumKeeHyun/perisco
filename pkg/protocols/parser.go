package protocols

import (
	"errors"

	"github.com/KumKeeHyun/perisco/perisco/bpf"
)

var (
	ErrNotExistsHeader = errors.New("protocols: not exists header")
)

type RequestHeader interface {
	GetSockKey() bpf.SockKey
	GetProtoType() bpf.ProtocolType
	RequestHeader()
}

type ResponseHeader interface {
	GetSockKey() bpf.SockKey
	GetProtoType() bpf.ProtocolType
	ResponseHeader()
}

type ProtoParser interface {
	GetProtoType() bpf.ProtocolType
	ParseRequest(msg *bpf.MsgEvent) ([]RequestHeader, error)
	ParseResponse(msg *bpf.MsgEvent) ([]ResponseHeader, error)
}


type ReqRespParser struct {
	sendc chan *bpf.MsgEvent
	recvc chan *bpf.MsgEvent

	reqc  chan RequestHeader
	respc chan ResponseHeader

	protoParsers map[bpf.ProtocolType]ProtoParser
}


type UnknownParser struct {
	parserMap map[bpf.ProtocolType]ProtoParser
	protoMap  *bpf.ProtocolMap
}

var _ ProtoParser = &UnknownParser{}

// GetProtoType implements ProtoParser
func (*UnknownParser) GetProtoType() bpf.ProtocolType {
	return bpf.PROTO_UNKNOWN
}

// ParseRequest implements ProtoParser
func (p *UnknownParser) ParseRequest(msg *bpf.MsgEvent) ([]RequestHeader, error) {
	for pt, pp := range p.parserMap {
		if rhs, err := pp.ParseRequest(msg); err == nil {
			p.protoMap.Update(msg.SockKey.ToEndpointKey(), pt)
			return rhs, nil
		}
	}
	panic("unimplemented")
}

// ParseResponse implements ProtoParser
func (p *UnknownParser) ParseResponse(msg *bpf.MsgEvent) ([]ResponseHeader, error) {
	panic("unimplemented")
}