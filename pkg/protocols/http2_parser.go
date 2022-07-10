package protocols

import (
	"bytes"
	"fmt"
	"io"

	"github.com/KumKeeHyun/perisco/perisco/bpf"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

type HTTP2RequestHeader struct {
	SockKey     bpf.SockKey
	MetaHeaders *http2.MetaHeadersFrame
}

var _ RequestHeader = &HTTP2RequestHeader{}

// GetSockKey implements RequestHeader
func (rh *HTTP2RequestHeader) GetSockKey() bpf.SockKey {
	return rh.SockKey
}

// GetProtoType implements RequestHeader
func (rh *HTTP2RequestHeader) GetProtoType() bpf.ProtocolType {
	return bpf.HTTP2
}

// RequestHeader implements RequestHeader
func (*HTTP2RequestHeader) RequestHeader() {}

func (rh *HTTP2RequestHeader) String() string {
	return fmt.Sprintf("%s\n%v\n",
		rh.SockKey.String(),
		rh.MetaHeaders.Fields,
	)
}

type HTTP2ResponseHeader struct {
	SockKey     bpf.SockKey
	MetaHeaders *http2.MetaHeadersFrame
}

var _ ResponseHeader = &HTTP2ResponseHeader{}

// GetSockKey implements ResponseHeader
func (rh *HTTP2ResponseHeader) GetSockKey() bpf.SockKey {
	return rh.SockKey
}

// GetProtoType implements ResponseHeader
func (rh *HTTP2ResponseHeader) GetProtoType() bpf.ProtocolType {
	return bpf.HTTP2
}

// ResponseHeader implements ResponseHeader
func (*HTTP2ResponseHeader) ResponseHeader() {}

func (rh *HTTP2ResponseHeader) String() string {
	return fmt.Sprintf("%s\n%v\n",
		rh.SockKey.String(),
		rh.MetaHeaders.Fields,
	)
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
func (p *HTTP2Parser) ParseRequest(msg *bpf.MsgEvent) ([]RequestHeader, error) {
	br := bytes.NewReader(msg.Msg[:])
	skipPrefaceIfExists(br)

	f := http2.NewFramer(io.Discard, br)
	f.ReadMetaHeaders = p.getReqDec(&msg.SockKey)

	rhs := make([]RequestHeader, 0, 1)
	for {
		fr, err := f.ReadFrame()
		if err != nil {
			break
		}
		mh, ok := fr.(*http2.MetaHeadersFrame)
		if !ok {
			continue
		}
		rhs = append(rhs, &HTTP2RequestHeader{
			SockKey:     msg.SockKey,
			MetaHeaders: mh,
		})
	}

	if len(rhs) == 0 {
		return nil, ErrNotExistsHeader
	}
	return rhs, nil
}

func skipPrefaceIfExists(r *bytes.Reader) {
	preface := make([]byte, len(http2.ClientPreface))
	r.Read(preface)
	if !bytes.Equal(preface, []byte(http2.ClientPreface)) {
		r.Seek(0, 0)
	}
}

// ParseResponse implements ProtoParser
func (p *HTTP2Parser) ParseResponse(msg *bpf.MsgEvent) ([]ResponseHeader, error) {
	br := bytes.NewReader(msg.Msg[:])
	skipPrefaceIfExists(br)

	f := http2.NewFramer(io.Discard, br)
	f.ReadMetaHeaders = p.getRespDec(&msg.SockKey)

	rhs := make([]ResponseHeader, 0, 1)
	for {
		fr, err := f.ReadFrame()
		if err != nil {
			break
		}
		mh, ok := fr.(*http2.MetaHeadersFrame)
		if !ok {
			continue
		}
		rhs = append(rhs, &HTTP2ResponseHeader{
			SockKey:     msg.SockKey,
			MetaHeaders: mh,
		})
	}

	if len(rhs) == 0 {
		return nil, ErrNotExistsHeader
	}
	return rhs, nil
}
