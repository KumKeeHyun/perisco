package protocols

import (
	"bytes"
	"fmt"
	"io"
	"strings"

	"github.com/KumKeeHyun/perisco/perisco/bpf"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

type HTTP2RequestRecord struct {
	headerFrames []*http2.MetaHeadersFrame
}

var _ RequestRecord = &HTTP2RequestRecord{}

// ProtoType implements RequestRecord
func (*HTTP2RequestRecord) ProtoType() bpf.ProtocolType { return bpf.HTTP2 }

// RequestRecord implements RequestRecord
func (*HTTP2RequestRecord) RequestRecord() {}

// String implements RequestRecord
func (rr *HTTP2RequestRecord) String() string {
	builder := strings.Builder{}

	for _, hf := range rr.headerFrames {
		builder.WriteString(fmt.Sprintf("%v\n", hf.Fields))
	}

	return builder.String()
}

type HTTP2ResponseRecord struct {
	headerFrames []*http2.MetaHeadersFrame
}

var _ ResponseRecord = &HTTP2ResponseRecord{}

// ProtoType implements ResponseRecord
func (*HTTP2ResponseRecord) ProtoType() bpf.ProtocolType { return bpf.HTTP2 }

// ResponseRecord implements ResponseRecord
func (*HTTP2ResponseRecord) ResponseRecord() {}

// String implements ResponseRecord
func (rr *HTTP2ResponseRecord) String() string {
	builder := strings.Builder{}

	for _, hf := range rr.headerFrames {
		builder.WriteString(fmt.Sprintf("%v\n", hf.Fields))
	}

	return builder.String()
}

type HTTP2Parser struct {
	reqDecMap  map[bpf.SockKey]*hpack.Decoder
	respDecMap map[bpf.SockKey]*hpack.Decoder
}

func NewHTTP2Parser() *HTTP2Parser {
	return &HTTP2Parser{
		reqDecMap:  make(map[bpf.SockKey]*hpack.Decoder, 100),
		respDecMap: make(map[bpf.SockKey]*hpack.Decoder, 100),
	}
}

var _ ProtoParser = &HTTP2Parser{}

// GetProtoType implements ProtoParser
func (p *HTTP2Parser) GetProtoType() bpf.ProtocolType {
	return bpf.HTTP1
}

func (p *HTTP2Parser) getReqDec(key *bpf.SockKey) *hpack.Decoder {
	dec, exists := p.reqDecMap[*key]
	if !exists {
		dec = hpack.NewDecoder(4096, nil)
		p.reqDecMap[*key] = dec
	}
	return dec
}

func (p *HTTP2Parser) getRespDec(key *bpf.SockKey) *hpack.Decoder {
	dec, exists := p.respDecMap[*key]
	if !exists {
		dec = hpack.NewDecoder(4096, nil)
		p.respDecMap[*key] = dec
	}
	return dec
}

// ParseRequest implements ProtoParser
func (p *HTTP2Parser) ParseRequest(sockKey *bpf.SockKey, msg []byte) (RequestRecord, error) {
	br := bytes.NewReader(msg)
	skipPrefaceIfExists(br)

	f := http2.NewFramer(io.Discard, br)
	f.ReadMetaHeaders = p.getReqDec(sockKey)

	rr := &HTTP2RequestRecord{
		headerFrames: make([]*http2.MetaHeadersFrame, 0, 1),
	}
	for {
		fr, err := f.ReadFrame()
		if err != nil {
			break
		}
		mh, ok := fr.(*http2.MetaHeadersFrame)
		if !ok {
			continue
		}
		rr.headerFrames = append(rr.headerFrames, mh)
	}

	if len(rr.headerFrames) == 0 {
		return nil, ErrNotExistsHeader
	}
	return rr, nil
}

func skipPrefaceIfExists(r *bytes.Reader) {
	preface := make([]byte, len(http2.ClientPreface))
	r.Read(preface)
	if !bytes.Equal(preface, []byte(http2.ClientPreface)) {
		r.Seek(0, 0)
	}
}

// ParseResponse implements ProtoParser
func (p *HTTP2Parser) ParseResponse(sockKey *bpf.SockKey, msg []byte) (ResponseRecord, error) {
	br := bytes.NewReader(msg)
	skipPrefaceIfExists(br)

	f := http2.NewFramer(io.Discard, br)
	f.ReadMetaHeaders = p.getRespDec(sockKey)

	rr := &HTTP2ResponseRecord{
		headerFrames: make([]*http2.MetaHeadersFrame, 0, 1),
	}
	for {
		fr, err := f.ReadFrame()
		if err != nil {
			break
		}
		mh, ok := fr.(*http2.MetaHeadersFrame)
		if !ok {
			continue
		}
		rr.headerFrames = append(rr.headerFrames, mh)
	}

	if len(rr.headerFrames) == 0 {
		return nil, ErrNotExistsHeader
	}
	return rr, nil
}
