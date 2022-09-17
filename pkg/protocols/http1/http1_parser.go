package http1

import (
	"bufio"
	"bytes"
	"fmt"
	"net/http"

	"github.com/KumKeeHyun/perisco/pkg/ebpf/types"
	"github.com/KumKeeHyun/perisco/pkg/protocols"
)

type HTTP1RequestRecord struct {
	H1Req *http.Request
}

var _ protocols.RequestRecord = &HTTP1RequestRecord{}

// ProtoType implements RequestRecord
func (*HTTP1RequestRecord) ProtoType() types.ProtocolType { return types.HTTP1 }

// RequestRecord implements RequestRecord
func (*HTTP1RequestRecord) RequestRecord() {}

// String implements RequestRecord
func (rr *HTTP1RequestRecord) String() string {
	return fmt.Sprintf("%s %s %s %s\n%v",
		rr.H1Req.Proto,
		rr.H1Req.Method,
		rr.H1Req.RequestURI,
		rr.H1Req.Host,
		rr.H1Req.Header,
	)
}

type HTTP1ResponseRecord struct {
	H1Resp *http.Response
}

var _ protocols.ResponseRecord = &HTTP1ResponseRecord{}

// ProtoType implements ResponseRecord
func (*HTTP1ResponseRecord) ProtoType() types.ProtocolType { return types.HTTP1 }

// ResponseRecord implements ResponseRecord
func (*HTTP1ResponseRecord) ResponseRecord() {}

// String implements ResponseRecord
func (rr *HTTP1ResponseRecord) String() string {
	return fmt.Sprintf("%s %s\n%v",
		rr.H1Resp.Proto,
		rr.H1Resp.Status,
		rr.H1Resp.Header,
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

var _ protocols.ProtoParser = &HTTP1Parser{}

// GetProtoType implements ProtoParser
func (p *HTTP1Parser) ProtoType() types.ProtocolType {
	return types.HTTP1
}

// ParseRequest implements ProtoParser
func (p *HTTP1Parser) ParseRequest(_ *types.SockKey, msg []byte) ([]protocols.RequestRecord, error) {
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

	return []protocols.RequestRecord{&HTTP1RequestRecord{H1Req: req}}, nil
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
func (p *HTTP1Parser) ParseResponse(_ *types.SockKey, msg []byte) ([]protocols.ResponseRecord, error) {
	r := p.respReader
	br := bytes.NewReader(msg)
	r.Reset(br)

	resp, err := http.ReadResponse(r, nil)
	if err != nil {
		return nil, err
	}
	resp.Body.Close()

	return []protocols.ResponseRecord{&HTTP1ResponseRecord{H1Resp: resp}}, nil
}
