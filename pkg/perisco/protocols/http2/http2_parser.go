package http2

import (
	"bytes"
	"fmt"
	"io"
	"strconv"

	pb "github.com/KumKeeHyun/perisco/api/v1/perisco"
	"github.com/KumKeeHyun/perisco/pkg/ebpf/types"
	"github.com/KumKeeHyun/perisco/pkg/perisco/protocols"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

type HTTP2Request struct {
	Record *http2.MetaHeadersFrame
}

var _ protocols.ProtoRequest = &HTTP2Request{}

// ProtoType implements ProtoRequest
func (*HTTP2Request) ProtoType() types.ProtocolType { return types.HTTP2 }

// Protobuf implements ProtoRequest
func (r *HTTP2Request) Protobuf() *pb.Request {
	return &pb.Request{
		Record: &pb.Request_Http{
			Http: &pb.HTTPRequest{
				Protocol: "HTTP/2.0",
				Method: r.Record.PseudoValue("method"),
				Url: r.Record.PseudoValue("path"),
				Headers: toProtobufHeader(r.Record),
			},
		},
	}
}

func toProtobufHeader(hf *http2.MetaHeadersFrame) []*pb.HTTPHeader {
	fields := hf.RegularFields()
	res := make([]*pb.HTTPHeader, 0, len(fields)) 

	for _, f := range fields {
		res = append(res, &pb.HTTPHeader{Key: f.Name, Value: f.Value})
	}
	return res
}

// String implements ProtoRequest
func (rr *HTTP2Request) String() string {
	return fmt.Sprintf("%v", rr.Record.Fields)
}

type HTTP2Response struct {
	Record *http2.MetaHeadersFrame
}

var _ protocols.ProtoResponse = &HTTP2Response{}

// ProtoType implements ProtoResponse
func (*HTTP2Response) ProtoType() types.ProtocolType { return types.HTTP2 }

// Protobuf implements ProtoResponse
func (r *HTTP2Response) Protobuf() *pb.Response {
	code, _ := strconv.Atoi(r.Record.PseudoValue("status"))
	
	return &pb.Response{
		Record: &pb.Response_Http{
			Http: &pb.HTTPResponse{
				Protocol: r.Record.PseudoValue("scheme"),
				Code: uint32(code),
				Headers: toProtobufHeader(r.Record),
			},
		},
	}
}

// String implements ProtoResponse
func (rr *HTTP2Response) String() string {
	return fmt.Sprintf("%v", rr.Record.Fields)
}

type HTTP2Parser struct {
	reqDecMap  map[types.SockKey]*hpack.Decoder
	respDecMap map[types.SockKey]*hpack.Decoder
}

func NewHTTP2Parser() *HTTP2Parser {
	return &HTTP2Parser{
		reqDecMap:  make(map[types.SockKey]*hpack.Decoder, 100),
		respDecMap: make(map[types.SockKey]*hpack.Decoder, 100),
	}
}

var _ protocols.ProtoParser = &HTTP2Parser{}

// GetProtoType implements ProtoParser
func (p *HTTP2Parser) ProtoType() types.ProtocolType {
	return types.HTTP2
}

func (p *HTTP2Parser) getReqDec(key *types.SockKey) *hpack.Decoder {
	dec, exists := p.reqDecMap[*key]
	if !exists {
		dec = hpack.NewDecoder(4096, nil)
		p.reqDecMap[*key] = dec
	}
	return dec
}

func (p *HTTP2Parser) getRespDec(key *types.SockKey) *hpack.Decoder {
	dec, exists := p.respDecMap[*key]
	if !exists {
		dec = hpack.NewDecoder(4096, nil)
		p.respDecMap[*key] = dec
	}
	return dec
}

// ParseRequest implements ProtoParser
func (p *HTTP2Parser) ParseRequest(sockKey *types.SockKey, msg []byte) ([]protocols.ProtoRequest, error) {
	br := bytes.NewReader(msg)
	skipPrefaceIfExists(br)

	f := http2.NewFramer(io.Discard, br)
	f.ReadMetaHeaders = p.getReqDec(sockKey)

	rrs := make([]protocols.ProtoRequest, 0, 1)
	for {
		fr, err := f.ReadFrame()
		if err != nil {
			break
		}
		mh, ok := fr.(*http2.MetaHeadersFrame)
		if !ok {
			continue
		}
		rrs = append(rrs, &HTTP2Request{mh})
	}

	if len(rrs) == 0 {
		return nil, protocols.ErrNotExistsHeader
	}
	return rrs, nil
}

func skipPrefaceIfExists(r *bytes.Reader) {
	preface := make([]byte, len(http2.ClientPreface))
	r.Read(preface)
	if !bytes.Equal(preface, []byte(http2.ClientPreface)) {
		r.Seek(0, 0)
	}
}

// ParseResponse implements ProtoParser
func (p *HTTP2Parser) ParseResponse(sockKey *types.SockKey, msg []byte) ([]protocols.ProtoResponse, error) {
	br := bytes.NewReader(msg)
	skipPrefaceIfExists(br)

	f := http2.NewFramer(io.Discard, br)
	f.ReadMetaHeaders = p.getRespDec(sockKey)

	rrs := make([]protocols.ProtoResponse, 0, 1)
	for {
		fr, err := f.ReadFrame()
		if err != nil {
			break
		}
		mh, ok := fr.(*http2.MetaHeadersFrame)
		if !ok {
			continue
		}
		rrs = append(rrs, &HTTP2Response{mh})
	}

	if len(rrs) == 0 {
		return nil, protocols.ErrNotExistsHeader
	}
	return rrs, nil
}
