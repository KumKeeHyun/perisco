package protocols

import "container/list"

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

var _ ProtoMatcher = &HTTP2Matcher{}

// MatchRequest implements ProtoMatcher
func (m *HTTP2Matcher) MatchRequest(req *Request) (*ProtoMessage, error) {
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

func (m *HTTP2Matcher) findResp(req *Request) *Response {
	for e := m.respQueue.Front(); e != nil; e = e.Next() {
		resp := e.Value.(*Response)
		respSID := resp.Record.(*HTTP2ResponseRecord).HeaderFrames.StreamID
		reqSID := req.Record.(*HTTP2RequestRecord).HeaderFrames.StreamID

		if resp.SockKey == req.SockKey && respSID == reqSID {
			return m.respQueue.Remove(e).(*Response)
		}
	}
	return nil
}

// MatchResponse implements ProtoMatcher
func (m *HTTP2Matcher) MatchResponse(resp *Response) (*ProtoMessage, error) {
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

func (m *HTTP2Matcher) findReq(resp *Response) *Request {
	for e := m.reqQueue.Front(); e != nil; e = e.Next() {
		req := e.Value.(*Request)
		reqSID := req.Record.(*HTTP2RequestRecord).HeaderFrames.StreamID
		respSID := resp.Record.(*HTTP2ResponseRecord).HeaderFrames.StreamID

		if e.Value.(*Request).SockKey == resp.SockKey && reqSID == respSID {
			return m.reqQueue.Remove(e).(*Request)
		}
	}
	return nil
}