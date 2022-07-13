package protocols

import (
	"bufio"
	"bytes"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/KumKeeHyun/perisco/pkg/ebpf/types"
	"golang.org/x/net/http2"
)

func TestHTTP1RequestRecord_ProtoType(t *testing.T) {
	tests := []struct {
		name string
		want types.ProtocolType
	}{
		{
			name: "HTTP1 Request Record Protocol Type",
			want: types.HTTP1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := &HTTP1RequestRecord{}
			if got := h.ProtoType(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("HTTP1RequestRecord.ProtoType() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestHTTP1ResponseRecord_ProtoType(t *testing.T) {
	tests := []struct {
		name string
		want types.ProtocolType
	}{
		{
			name: "HTTP1 Response Record Protocol Type",
			want: types.HTTP1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := &HTTP1ResponseRecord{}
			if got := h.ProtoType(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("HTTP1ResponseRecord.ProtoType() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestHTTP1Parser_GetProtoType(t *testing.T) {
	tests := []struct {
		name string
		want types.ProtocolType
	}{
		{
			name: "HTTP1 Parser Protocol Type",
			want: types.HTTP1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := NewHTTP1Parser()
			if got := p.GetProtoType(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("HTTP1Parser.GetProtoType() = %v, want %v", got, tt.want)
			}
		})
	}
}

type http1Parser_ParseRequest_Test struct {
	name    string
	req     *http.Request
	wantErr bool
}

func (t *http1Parser_ParseRequest_Test) args() []byte {
	buf := bytes.NewBuffer(make([]byte, 0, 4096))
	t.req.Write(buf)

	len := buf.Len()
	if len > 4096 {
		len = 4096
	}
	return buf.Bytes()[:len]
}

func (t *http1Parser_ParseRequest_Test) want() RequestRecord {
	return &HTTP1RequestRecord{h1Req: t.req}
}

func (t *http1Parser_ParseRequest_Test) equal(got RequestRecord) bool {
	h1rr, ok := got.(*HTTP1RequestRecord)
	if !ok {
		return false
	}
	wantBytes := make([]byte, 0, 4096)
	t.req.Write(bytes.NewBuffer(wantBytes))
	gotBytes := make([]byte, 0, 4096)
	h1rr.h1Req.Write(bytes.NewBuffer(gotBytes))

	return bytes.Equal(wantBytes, gotBytes)
}

func TestHTTP1Parser_ParseRequest(t *testing.T) {
	tests := []http1Parser_ParseRequest_Test{
		{
			name: "Short Header Get Request",
			req: func() *http.Request {
				req, _ := http.NewRequest(http.MethodGet, "http://perisco.org/test/url", nil)
				req.Header.Add("User-Agent", "test-clinet/1.1")
				return req
			}(),
			wantErr: false,
		},
		{
			name: "Long Header Get Request",
			req: func() *http.Request {
				req, _ := http.NewRequest(http.MethodGet, "http://perisco.org/test/url", nil)
				req.Header.Add("User-Agent", "test-clinet/1.1")
				req.Header.Add("Long-Cookie", strings.Repeat("1234567890", 500))
				return req
			}(),
			wantErr: true,
		},
		{
			name: "Short Header Short Body Post Request",
			req: func() *http.Request {
				body := bytes.NewReader([]byte(strings.Repeat("1234567890", 10)))
				req, _ := http.NewRequest(http.MethodPost, "http://perisco.org/test/url", body)
				req.Header.Add("User-Agent", "test-clinet/1.1")
				return req
			}(),
			wantErr: false,
		},
		{
			name: "Short Header Long Body Post Request",
			req: func() *http.Request {
				body := bytes.NewReader([]byte(strings.Repeat("1234567890", 500)))
				req, _ := http.NewRequest(http.MethodPost, "http://perisco.org/test/url", body)
				req.Header.Add("User-Agent", "test-clinet/1.1")
				return req
			}(),
			wantErr: false,
		},
		{
			name: "Long Header Long Body Post Request",
			req: func() *http.Request {
				body := bytes.NewReader([]byte(strings.Repeat("1234567890", 500)))
				req, _ := http.NewRequest(http.MethodPost, "http://perisco.org/test/url", body)
				req.Header.Add("User-Agent", "test-clinet/1.1")
				req.Header.Add("Long-Cookie", strings.Repeat("1234567890", 500))
				return req
			}(),
			wantErr: true,
		},
		{
			name: "HTTP/2 Preface",
			req: func() *http.Request {
				req, _ := http.ReadRequest(bufio.NewReader(strings.NewReader(http2.ClientPreface)))
				return req
			}(),
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := NewHTTP1Parser()

			got, err := p.ParseRequest(nil, tt.args())
			if (err != nil) != tt.wantErr {
				t.Errorf("HTTP1Parser.ParseRequest() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				return
			}
			if !tt.equal(got) {
				t.Errorf("HTTP1Parser.ParseRequest() = %v, want %v", got, tt.want())
			}
		})
	}
}

func Test_validMethod(t *testing.T) {
	type args struct {
		req *http.Request
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		// valid
		{
			name: "Method GET",
			args: args{req: &http.Request{Method: http.MethodGet}},
			want: true,
		},
		{
			name: "Method Post",
			args: args{req: &http.Request{Method: http.MethodPost}},
			want: true,
		},
		{
			name: "Method Put",
			args: args{req: &http.Request{Method: http.MethodPut}},
			want: true,
		},
		{
			name: "Method Delete",
			args: args{req: &http.Request{Method: http.MethodDelete}},
			want: true,
		},
		{
			name: "Method Patch",
			args: args{req: &http.Request{Method: http.MethodPatch}},
			want: true,
		},
		{
			name: "Method Head",
			args: args{req: &http.Request{Method: http.MethodHead}},
			want: true,
		},
		{
			name: "Method Options",
			args: args{req: &http.Request{Method: http.MethodOptions}},
			want: true,
		},
		{
			name: "Method Connect",
			args: args{req: &http.Request{Method: http.MethodConnect}},
			want: true,
		},
		{
			name: "Method Trace",
			args: args{req: &http.Request{Method: http.MethodTrace}},
			want: true,
		},

		// invalid
		{
			name: "Method PRI",
			args: args{req: &http.Request{Method: "PRI"}},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := validMethod(tt.args.req); got != tt.want {
				t.Errorf("isValidMethod() = %v, want %v", got, tt.want)
			}
		})
	}
}

type http1Parser_ParseResponse_Test struct {
	name    string
	resp    *http.Response
	wantErr bool
}

func (t *http1Parser_ParseResponse_Test) args() []byte {
	buf := bytes.NewBuffer(make([]byte, 0, 4096))
	t.resp.Write(buf)

	len := buf.Len()
	if len > 4096 {
		len = 4096
	}
	return buf.Bytes()[:len]
}

func (t *http1Parser_ParseResponse_Test) want() ResponseRecord {
	return &HTTP1ResponseRecord{h1Resp: t.resp}
}

func (t *http1Parser_ParseResponse_Test) equal(got ResponseRecord) bool {
	h1rr, ok := got.(*HTTP1ResponseRecord)
	if !ok {
		return false
	}
	wantBytes := make([]byte, 0, 4096)
	t.resp.Write(bytes.NewBuffer(wantBytes))
	gotBytes := make([]byte, 0, 4096)
	h1rr.h1Resp.Write(bytes.NewBuffer(gotBytes))

	return bytes.Equal(wantBytes, gotBytes)
}

func TestHTTP1Parser_ParseResponse(t *testing.T) {
	tests := []http1Parser_ParseResponse_Test{
		{
			name: "Short Header Short Body",
			resp: func() *http.Response {
				resp := &http.Response{}
				resp.Proto = "HTTP/1.1"
				resp.StatusCode = http.StatusOK
				resp.Header = make(http.Header)
				resp.Header.Add("User-Agent", "test-clinet/1.1")
				resp.Body = io.NopCloser(bytes.NewReader([]byte(strings.Repeat("1234567890", 10))))

				return resp
			}(),
			wantErr: false,
		},
		{
			name: "Short Header Long Body",
			resp: func() *http.Response {
				resp := &http.Response{}
				resp.Proto = "HTTP/1.1"
				resp.StatusCode = http.StatusOK
				resp.Header = make(http.Header)
				resp.Header.Add("User-Agent", "test-clinet/1.1")
				resp.Body = io.NopCloser(bytes.NewReader([]byte(strings.Repeat("1234567890", 500))))
				return resp
			}(),
			wantErr: false,
		},
		{
			name: "Long Header Short Body",
			resp: func() *http.Response {
				resp := &http.Response{}
				resp.Proto = "HTTP/1.1"
				resp.StatusCode = http.StatusOK
				resp.Header = make(http.Header)
				resp.Header.Add("User-Agent", "test-clinet/1.1")
				resp.Header.Add("Long-Cookie", strings.Repeat("1234567890", 500))
				resp.Body = io.NopCloser(bytes.NewReader([]byte(strings.Repeat("1234567890", 10))))
				return resp
			}(),
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := NewHTTP1Parser()

			got, err := p.ParseResponse(nil, tt.args())
			if (err != nil) != tt.wantErr {
				t.Errorf("HTTP1Parser.ParseResponse() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				return
			}
			if !tt.equal(got) {
				t.Errorf("HTTP1Parser.ParseResponse() = %v, want %v", got, tt.want())
			}
		})
	}
}
