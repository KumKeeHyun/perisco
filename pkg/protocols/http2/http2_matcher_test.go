package http2

import (
	"container/list"
	"reflect"
	"testing"

	"github.com/KumKeeHyun/perisco/pkg/ebpf/types"
	"github.com/KumKeeHyun/perisco/pkg/protocols"
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
		req *protocols.Request
	}
	tests := []struct {
		name   string
		args   args
		fields fields
		want   bool
	}{
		{
			name: "Success to Find Response",
			args: args{
				req: &protocols.Request{
					SockKey: types.SockKey{Pid: 1},
					Record: &HTTP2Request{
						Record: getHeaderFramWithStreamID(1),
					},
				},
			},
			fields: fields{
				reqQueue: list.New(),
				respQueue: func() *list.List {
					l := list.New()
					l.PushFront(&protocols.Response{
						SockKey: types.SockKey{Pid: 1},
						Record: &HTTP2Response{
							Record: getHeaderFramWithStreamID(1),
						},
					})
					return l
				}(),
			},
			want: true,
		},
		{
			name: "Empty Response Queue",
			args: args{
				req: &protocols.Request{
					SockKey: types.SockKey{Pid: 1},
					Record: &HTTP2Request{
						Record: getHeaderFramWithStreamID(1),
					},
				},
			},
			fields: fields{
				reqQueue:  list.New(),
				respQueue: list.New(),
			},
			want: false,
		},
		{
			name: "Fail to Find Response pid",
			args: args{
				req: &protocols.Request{
					SockKey: types.SockKey{Pid: 1},
					Record: &HTTP2Request{
						Record: getHeaderFramWithStreamID(1),
					},
				},
			},
			fields: fields{
				reqQueue: list.New(),
				respQueue: func() *list.List {
					l := list.New()
					l.PushFront(&protocols.Response{
						SockKey: types.SockKey{Pid: 2},
						Record: &HTTP2Response{
							Record: getHeaderFramWithStreamID(1),
						},
					})
					return l
				}(),
			},
			want: false,
		},
		{
			name: "Fail to Find Response streamID",
			args: args{
				req: &protocols.Request{
					SockKey: types.SockKey{Pid: 1},
					Record: &HTTP2Request{
						Record: getHeaderFramWithStreamID(1),
					},
				},
			},
			fields: fields{
				reqQueue: list.New(),
				respQueue: func() *list.List {
					l := list.New()
					l.PushFront(&protocols.Response{
						SockKey: types.SockKey{Pid: 1},
						Record: &HTTP2Response{
							Record: getHeaderFramWithStreamID(2),
						},
					})
					return l
				}(),
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &HTTP2Matcher{
				reqQueue:  tt.fields.reqQueue,
				respQueue: tt.fields.respQueue,
			}
			got := m.MatchRequest(tt.args.req)
			if (got != nil) != tt.want {
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
		req *protocols.Request
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   *protocols.Response
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
		resp *protocols.Response
	}
	tests := []struct {
		name   string
		args   args
		fields fields
		want   bool
	}{
		{
			name: "Success to Find Response",
			args: args{
				resp: &protocols.Response{
					SockKey: types.SockKey{Pid: 1},
					Record: &HTTP2Response{
						Record: getHeaderFramWithStreamID(1),
					},
				},
			},
			fields: fields{
				reqQueue: func() *list.List {
					l := list.New()
					l.PushFront(&protocols.Request{
						SockKey: types.SockKey{Pid: 1},
						Record: &HTTP2Request{
							Record: getHeaderFramWithStreamID(1),
						},
					})
					return l
				}(),
				respQueue: list.New(),
			},
			want: true,
		},
		{
			name: "Empty Response Queue",
			args: args{
				resp: &protocols.Response{
					SockKey: types.SockKey{Pid: 1},
					Record: &HTTP2Response{
						Record: getHeaderFramWithStreamID(1),
					},
				},
			},
			fields: fields{
				reqQueue:  list.New(),
				respQueue: list.New(),
			},
			want: false,
		},
		{
			name: "Fail to Find Response pid",
			args: args{
				resp: &protocols.Response{
					SockKey: types.SockKey{Pid: 1},
					Record: &HTTP2Response{
						Record: getHeaderFramWithStreamID(1),
					},
				},
			},
			fields: fields{
				reqQueue: func() *list.List {
					l := list.New()
					l.PushFront(&protocols.Request{
						SockKey: types.SockKey{Pid: 2},
						Record: &HTTP2Request{
							Record: getHeaderFramWithStreamID(1),
						},
					})
					return l
				}(),
				respQueue: list.New(),
			},
			want: false,
		},
		{
			name: "Fail to Find Response streamID",
			args: args{
				resp: &protocols.Response{
					SockKey: types.SockKey{Pid: 1},
					Record: &HTTP2Response{
						Record: getHeaderFramWithStreamID(1),
					},
				},
			},
			fields: fields{
				reqQueue: func() *list.List {
					l := list.New()
					l.PushFront(&protocols.Request{
						SockKey: types.SockKey{Pid: 1},
						Record: &HTTP2Request{
							Record: getHeaderFramWithStreamID(2),
						},
					})
					return l
				}(),
				respQueue: list.New(),
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &HTTP2Matcher{
				reqQueue:  tt.fields.reqQueue,
				respQueue: tt.fields.respQueue,
			}
			got := m.MatchResponse(tt.args.resp)
			if (got != nil) != tt.want {
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
		resp *protocols.Response
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   *protocols.Request
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
