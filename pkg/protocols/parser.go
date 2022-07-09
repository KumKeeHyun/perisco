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
	RequestHeader()
}

type ResponseHeader interface {
	GetSockKey() bpf.SockKey
	ResponseHeader()
}

type ProtoParser interface {
	ParseRequest(msg *bpf.MsgEvent) ([]RequestHeader, error)
	ParseResponse(msg *bpf.MsgEvent) ([]ResponseHeader, error)
}

type ReqRespParser struct {
	sendCh chan *bpf.MsgEvent
	recvCh chan *bpf.MsgEvent

	protoParser map[bpf.ProtocolType]ProtoParser
}