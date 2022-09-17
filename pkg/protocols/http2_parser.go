package protocols

import (
	"bytes"
	"fmt"
	"io"

	"github.com/KumKeeHyun/perisco/pkg/ebpf/types"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

type HTTP2RequestRecord struct {
	HeaderFrames *http2.MetaHeadersFrame
}

var _ RequestRecord = &HTTP2RequestRecord{}

// ProtoType implements RequestRecord
func (*HTTP2RequestRecord) ProtoType() types.ProtocolType { return types.HTTP2 }

// RequestRecord implements RequestRecord
func (*HTTP2RequestRecord) RequestRecord() {}

// String implements RequestRecord
func (rr *HTTP2RequestRecord) String() string {
	return fmt.Sprintf("%v", rr.HeaderFrames.Fields)
}

type HTTP2ResponseRecord struct {
	HeaderFrames *http2.MetaHeadersFrame
}

var _ ResponseRecord = &HTTP2ResponseRecord{}

// ProtoType implements ResponseRecord
func (*HTTP2ResponseRecord) ProtoType() types.ProtocolType { return types.HTTP2 }

// ResponseRecord implements ResponseRecord
func (*HTTP2ResponseRecord) ResponseRecord() {}

// String implements ResponseRecord
func (rr *HTTP2ResponseRecord) String() string {
	return fmt.Sprintf("%v", rr.HeaderFrames.Fields)
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

var _ ProtoParser = &HTTP2Parser{}

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
func (p *HTTP2Parser) ParseRequest(sockKey *types.SockKey, msg []byte) ([]RequestRecord, error) {
	br := bytes.NewReader(msg)
	skipPrefaceIfExists(br)

	f := http2.NewFramer(io.Discard, br)
	f.ReadMetaHeaders = p.getReqDec(sockKey)

	rrs := make([]RequestRecord, 0, 1)
	for {
		fr, err := f.ReadFrame()
		if err != nil {
			break
		}
		mh, ok := fr.(*http2.MetaHeadersFrame)
		if !ok {
			continue
		}
		rrs = append(rrs, &HTTP2RequestRecord{mh})
	}

	if len(rrs) == 0 {
		return nil, ErrNotExistsHeader
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
func (p *HTTP2Parser) ParseResponse(sockKey *types.SockKey, msg []byte) ([]ResponseRecord, error) {
	br := bytes.NewReader(msg)
	skipPrefaceIfExists(br)

	f := http2.NewFramer(io.Discard, br)
	f.ReadMetaHeaders = p.getRespDec(sockKey)

	rrs := make([]ResponseRecord, 0, 1)
	for {
		fr, err := f.ReadFrame()
		if err != nil {
			break
		}
		mh, ok := fr.(*http2.MetaHeadersFrame)
		if !ok {
			continue
		}
		rrs = append(rrs, &HTTP2ResponseRecord{mh})
	}

	if len(rrs) == 0 {
		return nil, ErrNotExistsHeader
	}
	return rrs, nil
}
