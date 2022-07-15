package protocols

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/KumKeeHyun/perisco/pkg/ebpf/types"
	"golang.org/x/net/http2/hpack"
)

func TestHTTP2RequestRecord_ProtoType(t *testing.T) {
	tests := []struct {
		name string
		want types.ProtocolType
	}{
		{
			name: "HTTP2 Request Record Protocol Type",
			want: types.HTTP2,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := &HTTP2RequestRecord{}
			if got := h.ProtoType(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("HTTP2RequestRecord.ProtoType() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestHTTP2ResponseRecord_ProtoType(t *testing.T) {
	tests := []struct {
		name string
		want types.ProtocolType
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := &HTTP2ResponseRecord{}
			if got := h.ProtoType(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("HTTP2ResponseRecord.ProtoType() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestHTTP2Parser_ProtoType(t *testing.T) {
	tests := []struct {
		name string
		want types.ProtocolType
	}{
		{
			name: "HTTP2 Parser Protocol Type",
			want: types.HTTP2,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := NewHTTP2Parser()
			if got := p.ProtoType(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("HTTP2Parser.GetProtoType() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestHTTP2Parser_getReqDec(t *testing.T) {
	type fields struct {
		reqDecMap  map[types.SockKey]*hpack.Decoder
		respDecMap map[types.SockKey]*hpack.Decoder
	}
	type args struct {
		key *types.SockKey
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   *hpack.Decoder
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &HTTP2Parser{
				reqDecMap:  tt.fields.reqDecMap,
				respDecMap: tt.fields.respDecMap,
			}
			if got := p.getReqDec(tt.args.key); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("HTTP2Parser.getReqDec() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestHTTP2Parser_getRespDec(t *testing.T) {
	type fields struct {
		reqDecMap  map[types.SockKey]*hpack.Decoder
		respDecMap map[types.SockKey]*hpack.Decoder
	}
	type args struct {
		key *types.SockKey
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   *hpack.Decoder
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &HTTP2Parser{
				reqDecMap:  tt.fields.reqDecMap,
				respDecMap: tt.fields.respDecMap,
			}
			if got := p.getRespDec(tt.args.key); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("HTTP2Parser.getRespDec() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestHTTP2Parser_ParseRequest(t *testing.T) {
	type fields struct {
		reqDecMap  map[types.SockKey]*hpack.Decoder
		respDecMap map[types.SockKey]*hpack.Decoder
	}
	type args struct {
		sockKey *types.SockKey
		msg     []byte
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    RequestRecord
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &HTTP2Parser{
				reqDecMap:  tt.fields.reqDecMap,
				respDecMap: tt.fields.respDecMap,
			}
			got, err := p.ParseRequest(tt.args.sockKey, tt.args.msg)
			if (err != nil) != tt.wantErr {
				t.Errorf("HTTP2Parser.ParseRequest() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("HTTP2Parser.ParseRequest() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_skipPrefaceIfExists(t *testing.T) {
	type args struct {
		r *bytes.Reader
	}
	tests := []struct {
		name string
		args args
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			skipPrefaceIfExists(tt.args.r)
		})
	}
}

func TestHTTP2Parser_ParseResponse(t *testing.T) {
	type fields struct {
		reqDecMap  map[types.SockKey]*hpack.Decoder
		respDecMap map[types.SockKey]*hpack.Decoder
	}
	type args struct {
		sockKey *types.SockKey
		msg     []byte
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    ResponseRecord
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &HTTP2Parser{
				reqDecMap:  tt.fields.reqDecMap,
				respDecMap: tt.fields.respDecMap,
			}
			got, err := p.ParseResponse(tt.args.sockKey, tt.args.msg)
			if (err != nil) != tt.wantErr {
				t.Errorf("HTTP2Parser.ParseResponse() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("HTTP2Parser.ParseResponse() = %v, want %v", got, tt.want)
			}
		})
	}
}
