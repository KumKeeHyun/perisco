package http2

import (
	"container/list"

	pb "github.com/KumKeeHyun/perisco/api/v1/perisco"
	"github.com/KumKeeHyun/perisco/pkg/protocols"
)

type HTTP2Matcher struct {
	reqQueue  *list.List
	respQueue *list.List
}

func NewHTTP2Matcher() *HTTP2Matcher {
	return &HTTP2Matcher{
		reqQueue:  list.New(),
		respQueue: list.New(),
	}
}

var _ protocols.ProtoMatcher = &HTTP2Matcher{}

// MatchRequest implements ProtoMatcher
func (m *HTTP2Matcher) MatchRequest(req *protocols.Request) *pb.ProtoMessage {
	resp := m.findResp(req)
	if resp == nil {
		m.reqQueue.PushBack(req)
		return nil
	}

	return protocols.ProtoMessage(req, resp)
}

func (m *HTTP2Matcher) findResp(req *protocols.Request) *protocols.Response {
	for e := m.respQueue.Front(); e != nil; e = e.Next() {
		resp := e.Value.(*protocols.Response)
		respSID := resp.Record.(*HTTP2Response).Record.StreamID
		reqSID := req.Record.(*HTTP2Request).Record.StreamID

		if resp.SockKey == req.SockKey && respSID == reqSID {
			return m.respQueue.Remove(e).(*protocols.Response)
		}
	}
	return nil
}

// MatchResponse implements ProtoMatcher
func (m *HTTP2Matcher) MatchResponse(resp *protocols.Response) *pb.ProtoMessage {
	req := m.findReq(resp)
	if req == nil {
		m.respQueue.PushBack(resp)
		return nil
	}

	return protocols.ProtoMessage(req, resp)
}

func (m *HTTP2Matcher) findReq(resp *protocols.Response) *protocols.Request {
	for e := m.reqQueue.Front(); e != nil; e = e.Next() {
		req := e.Value.(*protocols.Request)
		reqSID := req.Record.(*HTTP2Request).Record.StreamID
		respSID := resp.Record.(*HTTP2Response).Record.StreamID

		if e.Value.(*protocols.Request).SockKey == resp.SockKey && reqSID == respSID {
			return m.reqQueue.Remove(e).(*protocols.Request)
		}
	}
	return nil
}
