package http1

import (
	"bufio"
	"bytes"
	"fmt"
	"net/http"

	pb "github.com/KumKeeHyun/perisco/api/v1/perisco"
	"github.com/KumKeeHyun/perisco/pkg/ebpf/types"
	"github.com/KumKeeHyun/perisco/pkg/protocols"
)

type HTTP1Request struct {
	Record *http.Request
}

var _ protocols.ProtoRequest = &HTTP1Request{}

// ProtoType implements ProtoRequest
func (*HTTP1Request) ProtoType() types.ProtocolType { return types.HTTP1 }

// RequestRecord implements ProtoRequest
func (r *HTTP1Request) RequestRecord() *pb.Request {
	return &pb.Request{
		Record: &pb.Request_Http{
			Http: &pb.HTTPRequest{
				Protocol: r.Record.Proto,
				Method:   r.Record.Method,
				Url:      r.Record.RequestURI,
				Headers:  toProtobufHeader(r.Record.Header),
			},
		},
	}
}

func toProtobufHeader(header http.Header) []*pb.HTTPHeader {
	res := make([]*pb.HTTPHeader, 0, len(header))
	for k, vs := range header {
		for _, v := range vs {
			res = append(res, &pb.HTTPHeader{Key: k, Value: v})
		}
	}
	return res
}

// String implements ProtoRequest
func (rr *HTTP1Request) String() string {
	return fmt.Sprintf("%s %s %s %s\n%v",
		rr.Record.Proto,
		rr.Record.Method,
		rr.Record.RequestURI,
		rr.Record.Host,
		rr.Record.Header,
	)
}

type HTTP1Response struct {
	Record *http.Response
}

var _ protocols.ProtoResponse = &HTTP1Response{}

// ProtoType implements ProtoResponse
func (*HTTP1Response) ProtoType() types.ProtocolType { return types.HTTP1 }

// ResponseRecord implements ProtoResponse
func (r *HTTP1Response) ResponseRecord() *pb.Response {
	return &pb.Response{
		Record: &pb.Response_Http{
			Http: &pb.HTTPResponse{
				Protocol: r.Record.Proto,
				Code:     uint32(r.Record.StatusCode),
				Headers:  toProtobufHeader(r.Record.Header),
			},
		},
	}
}

// String implements ProtoResponse
func (rr *HTTP1Response) String() string {
	return fmt.Sprintf("%s %s\n%v",
		rr.Record.Proto,
		rr.Record.Status,
		rr.Record.Header,
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
func (p *HTTP1Parser) ParseRequest(_ *types.SockKey, msg []byte) ([]protocols.ProtoRequest, error) {
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

	return []protocols.ProtoRequest{&HTTP1Request{Record: req}}, nil
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
func (p *HTTP1Parser) ParseResponse(_ *types.SockKey, msg []byte) ([]protocols.ProtoResponse, error) {
	r := p.respReader
	br := bytes.NewReader(msg)
	r.Reset(br)

	resp, err := http.ReadResponse(r, nil)
	if err != nil {
		return nil, err
	}
	resp.Body.Close()

	return []protocols.ProtoResponse{&HTTP1Response{Record: resp}}, nil
}
