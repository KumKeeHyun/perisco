package protocols

import (
	"bufio"
	"bytes"
	"fmt"
	"net/http"

	"github.com/KumKeeHyun/perisco/perisco/bpf"
)

type HTTP1RequestRecord struct {
	h1Req *http.Request
}

var _ RequestRecord = &HTTP1RequestRecord{}

// ProtoType implements RequestRecord
func (*HTTP1RequestRecord) ProtoType() bpf.ProtocolType { return bpf.HTTP1 }

// RequestRecord implements RequestRecord
func (*HTTP1RequestRecord) RequestRecord() {}

// String implements RequestRecord
func (rr *HTTP1RequestRecord) String() string {
	return fmt.Sprintf("%s %s %s %s %d\n%v\n",
		rr.h1Req.Proto,
		rr.h1Req.Method,
		rr.h1Req.RequestURI,
		rr.h1Req.Host,
		rr.h1Req.ContentLength,
		rr.h1Req.Header,
	)
}


type HTTP1ResponseRecord struct {
	h1Resp *http.Response
}

var _ ResponseRecord = &HTTP1ResponseRecord{}

// ProtoType implements ResponseRecord
func (*HTTP1ResponseRecord) ProtoType() bpf.ProtocolType { return bpf.HTTP1 }

// ResponseRecord implements ResponseRecord
func (*HTTP1ResponseRecord) ResponseRecord() {}

// String implements ResponseRecord
func (rr *HTTP1ResponseRecord) String() string {
	return fmt.Sprintf("%s %s\n%v\n",
		rr.h1Resp.Proto,
		rr.h1Resp.Status,
		rr.h1Resp.Header,
	)
}

const h1ReaderBufSize = 4096

type HTTP1Parser struct {
	reqReader  *bufio.Reader
	respReader *bufio.Reader
}

func NewHTTP1Parser() *HTTP1Parser {
	return &HTTP1Parser{
		reqReader:  bufio.NewReaderSize(nil, h1ReaderBufSize),
		respReader: bufio.NewReaderSize(nil, h1ReaderBufSize),
	}
}

var _ ProtoParser = &HTTP1Parser{}

// GetProtoType implements ProtoParser
func (p *HTTP1Parser) GetProtoType() bpf.ProtocolType {
	return bpf.HTTP1
}

// ParseRequest implements ProtoParser
func (p *HTTP1Parser) ParseRequest(_ *bpf.SockKey, msg []byte) (RequestRecord, error) {
	r := p.reqReader
	br := bytes.NewReader(msg)
	r.Reset(br)

	req, err := http.ReadRequest(r)
	if err != nil {
		return nil, err
	}
	req.Body.Close()

	if !validMethod(req) {
		return nil, fmt.Errorf("invalid http method. got: %s", req.Method)
	}

	return &HTTP1RequestRecord{
		h1Req:   req,
	}, nil
}

func validMethod(req *http.Request) bool {
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
func (p *HTTP1Parser) ParseResponse(_ *bpf.SockKey, msg []byte) (ResponseRecord, error) {
	r := p.respReader
	br := bytes.NewReader(msg)
	r.Reset(br)

	resp, err := http.ReadResponse(r, nil)
	if err != nil {
		return nil, err
	}
	resp.Body.Close()

	return &HTTP1ResponseRecord{
		h1Resp: resp,
	}, nil
}
