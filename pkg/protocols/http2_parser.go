package protocols

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

type Http2RequestResult struct {
	Method string
	Path   string
	Header map[string]string
}

func (r *Http2RequestResult) String() string {
	return fmt.Sprintf("[ method: %s, path: %s, header: %v ]", r.Method, r.Path, r.Header)
}

type Http2ResponseResult struct {
	Status int
	Header map[string]string
}

func (r *Http2ResponseResult) String() string {
	return fmt.Sprintf("[ status: %d, header: %v ]", r.Status, r.Header)
}

type Http2Parser struct{}

var _ Parser = &Http2Parser{}

// ParseRequest implements protocols.Parser
func (*Http2Parser) ParseRequest(rawBytes []byte) (RequestResult, error) {
	r := bytes.NewReader(rawBytes)
	skipPrefaceIfExist(r)

	framer := http2.NewFramer(io.Discard, r)
	for {
		frame, err := framer.ReadFrame()
		if err != nil {
			break
		}
		headers, err := extractHeaders(frame)
		if err != nil {
			continue
		}
		return headersToRequest(headers), nil
	}
	return nil, errors.New("cannot find headers frame")
}

func headersToRequest(headers []hpack.HeaderField) *Http2RequestResult {
	req := &Http2RequestResult{
		Header: make(map[string]string),
	}
	for _, h := range headers {
		if h.Name == ":method" {
			req.Method = h.Value
		} else if h.Name == ":path" {
			req.Path = h.Value
		} else if strings.HasPrefix(h.Name, ":") {

		} else {
			req.Header[h.Name] = h.Value
		}
	}
	return req
}

func extractHeaders(frame http2.Frame) ([]hpack.HeaderField, error) {
	hFrame, ok := frame.(*http2.HeadersFrame)
	if !ok {
		return nil, errors.New("frame is not headers frame")
	}
	headers, err := hpack.NewDecoder(4096, nil).DecodeFull(hFrame.HeaderBlockFragment())
	if err != nil {
		return nil, err
	}
	return headers, nil
}

func skipPrefaceIfExist(r *bytes.Reader) {
	preface := make([]byte, len(http2.ClientPreface))
	r.Read(preface)
	if !bytes.Equal(preface, []byte(http2.ClientPreface)) {
		r.Seek(0, 0)
	}
}

// ParseResponse implements protocols.Parser
func (*Http2Parser) ParseResponse(rawBytes []byte) (ResponseResult, error) {
	r := bytes.NewReader(rawBytes)
	skipPrefaceIfExist(r)

	framer := http2.NewFramer(io.Discard, r)
	for {
		frame, err := framer.ReadFrame()
		if err != nil {
			break
		}
		headers, err := extractHeaders(frame)
		if err != nil {
			continue
		}
		return headersToResponse(headers), nil
	}
	return nil, errors.New("cannot find headers frame")
}

func headersToResponse(headers []hpack.HeaderField) *Http2ResponseResult {
	resp := &Http2ResponseResult{
		Header: make(map[string]string),
	}
	for _, h := range headers {
		if h.Name == ":status" {
			resp.Status, _ = strconv.Atoi(h.Value)
		} else if strings.HasPrefix(h.Name, ":") {

		} else {
			resp.Header[h.Name] = h.Value
		}
	}
	return resp
}
