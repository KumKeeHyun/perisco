package protocols

import (
	"container/list"
	"reflect"
	"testing"

	"github.com/KumKeeHyun/perisco/pkg/ebpf/types"
	"golang.org/x/net/http2"
)

func getHeaderFramWithStreamID(streamID uint32) *http2.MetaHeadersFrame {
	return &http2.MetaHeadersFrame{
		HeadersFrame: &http2.HeadersFrame{
			FrameHeader: http2.FrameHeader{StreamID: streamID},
		},
	}
}

func TestHTTP2Matcher_MatchRequest(t *testing.T) {
	type fields struct {
		reqQueue  *list.List
		respQueue *list.List
	}
	type args struct {
		req *Request
	}
	tests := []struct {
		name    string
		args    args
		fields  fields
		want    *ProtoMessage
		wantErr bool
	}{
		{
			name: "Success to Find Response",
			args: args{
				req: &Request{
					SockKey: types.SockKey{Pid: 1},
					Record: &HTTP2RequestRecord{
						HeaderFrames: getHeaderFramWithStreamID(1),
					},
				},
			},
			fields: fields{
				reqQueue: list.New(),
				respQueue: func() *list.List {
					l := list.New()
					l.PushFront(&Response{
						SockKey: types.SockKey{Pid: 1},
						Record: &HTTP2ResponseRecord{
							HeaderFrames: getHeaderFramWithStreamID(1),
						},
					})
					return l
				}(),
			},
			want: &ProtoMessage{
				SockKey: types.SockKey{Pid: 1},
				Req: &HTTP2RequestRecord{
					HeaderFrames: getHeaderFramWithStreamID(1),
				},
				Resp: &HTTP2ResponseRecord{
					HeaderFrames: getHeaderFramWithStreamID(1),
				},
			},
			wantErr: false,
		},
		{
			name: "Empty Response Queue",
			args: args{
				req: &Request{
					SockKey: types.SockKey{Pid: 1},
					Record: &HTTP2RequestRecord{
						HeaderFrames: getHeaderFramWithStreamID(1),
					},
				},
			},
			fields: fields{
				reqQueue: list.New(),
				respQueue: list.New(),
			},
			want: nil,
			wantErr: false,
		},
		{
			name: "Fail to Find Response pid",
			args: args{
				req: &Request{
					SockKey: types.SockKey{Pid: 1},
					Record: &HTTP2RequestRecord{
						HeaderFrames: getHeaderFramWithStreamID(1),
					},
				},
			},
			fields: fields{
				reqQueue: list.New(),
				respQueue: func() *list.List {
					l := list.New()
					l.PushFront(&Response{
						SockKey: types.SockKey{Pid: 2},
						Record: &HTTP2ResponseRecord{
							HeaderFrames: getHeaderFramWithStreamID(1),
						},
					})
					return l
				}(),
			},
			want: nil,
			wantErr: false,
		},
		{
			name: "Fail to Find Response streamID",
			args: args{
				req: &Request{
					SockKey: types.SockKey{Pid: 1},
					Record: &HTTP2RequestRecord{
						HeaderFrames: getHeaderFramWithStreamID(1),
					},
				},
			},
			fields: fields{
				reqQueue: list.New(),
				respQueue: func() *list.List {
					l := list.New()
					l.PushFront(&Response{
						SockKey: types.SockKey{Pid: 1},
						Record: &HTTP2ResponseRecord{
							HeaderFrames: getHeaderFramWithStreamID(2),
						},
					})
					return l
				}(),
			},
			want: nil,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &HTTP2Matcher{
				reqQueue:  tt.fields.reqQueue,
				respQueue: tt.fields.respQueue,
			}
			got, err := m.MatchRequest(tt.args.req)
			if (err != nil) != tt.wantErr {
				t.Errorf("HTTP2Matcher.MatchRequest() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("HTTP2Matcher.MatchRequest() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestHTTP2Matcher_findResp(t *testing.T) {
	type fields struct {
		reqQueue  *list.List
		respQueue *list.List
	}
	type args struct {
		req *Request
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   *Response
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &HTTP2Matcher{
				reqQueue:  tt.fields.reqQueue,
				respQueue: tt.fields.respQueue,
			}
			if got := m.findResp(tt.args.req); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("HTTP2Matcher.findResp() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestHTTP2Matcher_MatchResponse(t *testing.T) {
	type fields struct {
		reqQueue  *list.List
		respQueue *list.List
	}
	type args struct {
		resp *Response
	}
	tests := []struct {
		name    string
		args    args
		fields  fields
		want    *ProtoMessage
		wantErr bool
	}{
		{
			name: "Success to Find Response",
			args: args{
				resp: &Response{
					SockKey: types.SockKey{Pid: 1},
					Record: &HTTP2ResponseRecord{
						HeaderFrames: getHeaderFramWithStreamID(1),
					},
				},
			},
			fields: fields{
				reqQueue: func() *list.List {
					l := list.New()
					l.PushFront(&Request{
						SockKey: types.SockKey{Pid: 1},
						Record: &HTTP2RequestRecord{
							HeaderFrames: getHeaderFramWithStreamID(1),
						},
					})
					return l
				}(),
				respQueue: list.New(),
			},
			want: &ProtoMessage{
				SockKey: types.SockKey{Pid: 1},
				Req: &HTTP2RequestRecord{
					HeaderFrames: getHeaderFramWithStreamID(1),
				},
				Resp: &HTTP2ResponseRecord{
					HeaderFrames: getHeaderFramWithStreamID(1),
				},
			},
			wantErr: false,
		},
		{
			name: "Empty Response Queue",
			args: args{
				resp: &Response{
					SockKey: types.SockKey{Pid: 1},
					Record: &HTTP2ResponseRecord{
						HeaderFrames: getHeaderFramWithStreamID(1),
					},
				},
			},
			fields: fields{
				reqQueue: list.New(),
				respQueue: list.New(),
			},
			want: nil,
			wantErr: false,
		},
		{
			name: "Fail to Find Response pid",
			args: args{
				resp: &Response{
					SockKey: types.SockKey{Pid: 1},
					Record: &HTTP2ResponseRecord{
						HeaderFrames: getHeaderFramWithStreamID(1),
					},
				},
			},
			fields: fields{
				reqQueue: func() *list.List {
					l := list.New()
					l.PushFront(&Request{
						SockKey: types.SockKey{Pid: 2},
						Record: &HTTP2RequestRecord{
							HeaderFrames: getHeaderFramWithStreamID(1),
						},
					})
					return l
				}(),
				respQueue: list.New(),
			},
			want: nil,
			wantErr: false,
		},
		{
			name: "Fail to Find Response streamID",
			args: args{
				resp: &Response{
					SockKey: types.SockKey{Pid: 1},
					Record: &HTTP2ResponseRecord{
						HeaderFrames: getHeaderFramWithStreamID(1),
					},
				},
			},
			fields: fields{
				reqQueue: func() *list.List {
					l := list.New()
					l.PushFront(&Request{
						SockKey: types.SockKey{Pid: 1},
						Record: &HTTP2RequestRecord{
							HeaderFrames: getHeaderFramWithStreamID(2),
						},
					})
					return l
				}(),
				respQueue: list.New(),
			},
			want: nil,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &HTTP2Matcher{
				reqQueue:  tt.fields.reqQueue,
				respQueue: tt.fields.respQueue,
			}
			got, err := m.MatchResponse(tt.args.resp)
			if (err != nil) != tt.wantErr {
				t.Errorf("HTTP2Matcher.MatchResponse() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("HTTP2Matcher.MatchResponse() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestHTTP2Matcher_findReq(t *testing.T) {
	type fields struct {
		reqQueue  *list.List
		respQueue *list.List
	}
	type args struct {
		resp *Response
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   *Request
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &HTTP2Matcher{
				reqQueue:  tt.fields.reqQueue,
				respQueue: tt.fields.respQueue,
			}
			if got := m.findReq(tt.args.resp); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("HTTP2Matcher.findReq() = %v, want %v", got, tt.want)
			}
		})
	}
}
