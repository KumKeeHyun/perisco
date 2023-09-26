package mysql

import (
	"container/list"

	"github.com/KumKeeHyun/perisco/api/v1/perisco"
	"github.com/KumKeeHyun/perisco/pkg/perisco/protocols"
)

type MySQLMatcher struct {
	reqQueue  *list.List
	respQueue *list.List
}

var _ protocols.ProtoMatcher = &MySQLMatcher{}

func NewMySQLMatcher() *MySQLMatcher {
	return &MySQLMatcher{
		reqQueue:  list.New(),
		respQueue: list.New(),
	}
}

// MatchRequest implements protocols.ProtoMatcher.
func (m *MySQLMatcher) MatchRequest(req *protocols.Request) *perisco.ProtoMessage {
	// TODO: 임시로 HTTP/1 가져옴. MySQL의 패킷 구조를 좀더 살펴봐야 함
	resp := m.findResp(req)
	if resp == nil {
		m.reqQueue.PushBack(req)
		return nil
	}
	return protocols.ProtoMessage(req, resp)
}

func (m *MySQLMatcher) findResp(req *protocols.Request) *protocols.Response {
	for e := m.respQueue.Front(); e != nil; e = e.Next() {
		resp := e.Value.(*protocols.Response)

		if resp.SockKey == req.SockKey {
			return m.respQueue.Remove(e).(*protocols.Response)
		}
	}
	return nil
}

// MatchResponse implements protocols.ProtoMatcher.
func (m *MySQLMatcher) MatchResponse(resp *protocols.Response) *perisco.ProtoMessage {
	// TODO: 임시로 HTTP/1 가져옴. MySQL의 패킷 구조를 좀더 살펴봐야 함
	req := m.findReq(resp)
	if req == nil {
		m.respQueue.PushBack(resp)
		return nil
	}

	return protocols.ProtoMessage(req, resp)
}

func (m *MySQLMatcher) findReq(resp *protocols.Response) *protocols.Request {
	for e := m.reqQueue.Front(); e != nil; e = e.Next() {
		req := e.Value.(*protocols.Request)

		if req.SockKey == resp.SockKey {
			return m.reqQueue.Remove(e).(*protocols.Request)
		}
	}
	return nil
}
