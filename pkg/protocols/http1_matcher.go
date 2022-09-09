package protocols

import (
	"container/list"
)

var ()

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

var _ ProtoMatcher = &HTTP1Matcher{}

// MatchRequest implements ProtoMatcher
func (m *HTTP1Matcher) MatchRequest(req *Request) (*ProtoMessage, error) {
	resp := m.findResp(req)
	if resp == nil {
		m.reqQueue.PushBack(req)
		return nil, nil
	}
	return &ProtoMessage{
		SockKey: req.SockKey,
		Time:    resp.Timestamp - req.Timestamp,
		Req:     req.Record,
		Resp:    resp.Record,
	}, nil
}

func (m *HTTP1Matcher) findResp(req *Request) *Response {
	for e := m.respQueue.Front(); e != nil; e = e.Next() {
		if e.Value.(*Response).SockKey == req.SockKey {
			return m.respQueue.Remove(e).(*Response)
		}
	}
	return nil
}

// MatchResponse implements ProtoMatcher
func (m *HTTP1Matcher) MatchResponse(resp *Response) (*ProtoMessage, error) {
	req := m.findReq(resp)
	if req == nil {
		m.respQueue.PushBack(resp)
		return nil, nil
	}
	return &ProtoMessage{
		SockKey: resp.SockKey,
		Time:    resp.Timestamp - req.Timestamp,
		Req:     req.Record,
		Resp:    resp.Record,
	}, nil
}

func (m *HTTP1Matcher) findReq(resp *Response) *Request {
	for e := m.reqQueue.Front(); e != nil; e = e.Next() {
		if e.Value.(*Request).SockKey == resp.SockKey {
			return m.reqQueue.Remove(e).(*Request)
		}
	}
	return nil
}
