package protocols

import (
	"bufio"
	"bytes"
	"fmt"
	"net/http"

	"github.com/KumKeeHyun/perisco/perisco/bpf"
)

type HTTP1RequestHeader struct {
	SockKey bpf.SockKey
	Request *http.Request
}

var _ RequestHeader = &HTTP1RequestHeader{}

// GetSockKey implements RequestHeader
func (rh *HTTP1RequestHeader) GetSockKey() bpf.SockKey {
	return rh.SockKey
}

// GetProtoType implements RequestHeader
func (rh *HTTP1RequestHeader) GetProtoType() bpf.ProtocolType {
	return bpf.HTTP1
}

// RequestHeader implements RequestHeader
func (*HTTP1RequestHeader) RequestHeader() {}

func (rh *HTTP1RequestHeader) String() string {
	return fmt.Sprintf("%s\n%s %s %s %s %d\n%v\n",
		rh.SockKey.String(),
		rh.Request.Proto,
		rh.Request.Method,
		rh.Request.RequestURI,
		rh.Request.Host,
		rh.Request.ContentLength,
		rh.Request.Header,
	)
}

type HTTP1ResponseHeader struct {
	SockKey  bpf.SockKey
	Response *http.Response
}

var _ ResponseHeader = &HTTP1ResponseHeader{}

// GetSockKey implements ResponseHeader
func (rh *HTTP1ResponseHeader) GetSockKey() bpf.SockKey {
	return rh.SockKey
}

// GetProtoType implements ResponseHeader
func (rh *HTTP1ResponseHeader) GetProtoType() bpf.ProtocolType {
	return bpf.HTTP1
}

// ResponseHeader implements ResponseHeader
func (*HTTP1ResponseHeader) ResponseHeader() {}

func (rh *HTTP1ResponseHeader) String() string {
	return fmt.Sprintf("%s\n%s %s\n%v\n",
		rh.SockKey.String(),
		rh.Response.Proto,
		rh.Response.Status,
		rh.Response.Header,
	)
}

const bufSize = 4096

type HTTP1Parser struct {
	reqReader  *bufio.Reader
	respReader *bufio.Reader
}

func NewHTTP1Parser() *HTTP1Parser {
	return &HTTP1Parser{
		reqReader:  bufio.NewReaderSize(nil, bufSize),
		respReader: bufio.NewReaderSize(nil, bufSize),
	}
}

var _ ProtoParser = &HTTP1Parser{}

// GetProtoType implements ProtoParser
func (p *HTTP1Parser) GetProtoType() bpf.ProtocolType {
	return bpf.HTTP1
}

// ParseRequest implements ProtoParser
func (p *HTTP1Parser) ParseRequest(msg *bpf.MsgEvent) ([]RequestHeader, error) {
	r := p.reqReader
	br := bytes.NewReader(msg.GetBytes())
	r.Reset(br)

	req, err := http.ReadRequest(r)
	if err != nil {
		return nil, err
	}
	req.Body.Close()

	if !isValidMethod(req) {
		return nil, fmt.Errorf("invalid http method. got: %s", req.Method)
	}

	return []RequestHeader{
		&HTTP1RequestHeader{
			SockKey: msg.SockKey,
			Request: req,
		},
	}, nil
}

func isValidMethod(req *http.Request) bool {
	switch req.Method {
	case http.MethodGet,
		http.MethodPost,
		http.MethodPut,
		http.MethodDelete,
		http.MethodPatch,
		http.MethodHead,
		http.MethodOptions,
		http.MethodConnect,
		http.MethodTrace:
		return true
	default:
		return false
	}
}

// ParseResponse implements ProtoParser
func (p *HTTP1Parser) ParseResponse(msg *bpf.MsgEvent) ([]ResponseHeader, error) {
	r := p.respReader
	br := bytes.NewReader(msg.GetBytes())
	r.Reset(br)

	resp, err := http.ReadResponse(r, nil)
	if err != nil {
		return nil, err
	}
	resp.Body.Close()

	return []ResponseHeader{
		&HTTP1ResponseHeader{
			SockKey:  msg.SockKey,
			Response: resp,
		},
	}, nil
}
