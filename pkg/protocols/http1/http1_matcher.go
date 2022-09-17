package http1

import (
	"container/list"

	"github.com/KumKeeHyun/perisco/pkg/protocols"
)

type HTTP1Matcher struct {
	reqQueue  *list.List
	respQueue *list.List
}

func NewHTTP1Matcher() *HTTP1Matcher {
	return &HTTP1Matcher{
		reqQueue:  list.New(),
		respQueue: list.New(),
	}
}

var _ protocols.ProtoMatcher = &HTTP1Matcher{}

// MatchRequest implements ProtoMatcher
func (m *HTTP1Matcher) MatchRequest(req *protocols.Request) *protocols.ProtoMessage {
	resp := m.findResp(req)
	if resp == nil {
		m.reqQueue.PushBack(req)
		return nil
	}
	return &protocols.ProtoMessage{
		SockKey: req.SockKey,
		Time:    resp.Timestamp - req.Timestamp,
		Req:     req.Record,
		Resp:    resp.Record,
	}
}

func (m *HTTP1Matcher) findResp(req *protocols.Request) *protocols.Response {
	for e := m.respQueue.Front(); e != nil; e = e.Next() {
		if e.Value.(*protocols.Response).SockKey == req.SockKey {
			return m.respQueue.Remove(e).(*protocols.Response)
		}
	}
	return nil
}

// MatchResponse implements ProtoMatcher
func (m *HTTP1Matcher) MatchResponse(resp *protocols.Response) *protocols.ProtoMessage {
	req := m.findReq(resp)
	if req == nil {
		m.respQueue.PushBack(resp)
		return nil
	}
	return &protocols.ProtoMessage{
		SockKey: resp.SockKey,
		Time:    resp.Timestamp - req.Timestamp,
		Req:     req.Record,
		Resp:    resp.Record,
	}
}

func (m *HTTP1Matcher) findReq(resp *protocols.Response) *protocols.Request {
	for e := m.reqQueue.Front(); e != nil; e = e.Next() {
		if e.Value.(*protocols.Request).SockKey == resp.SockKey {
			return m.reqQueue.Remove(e).(*protocols.Request)
		}
	}
	return nil
}
