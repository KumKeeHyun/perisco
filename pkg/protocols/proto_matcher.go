package protocols

import (
	"fmt"
	"time"

	"github.com/KumKeeHyun/perisco/pkg/ebpf/types"
)

type ProtoMessage struct {
	SockKey     types.SockKey
	Timestamp   uint64
	LatencyNano uint64
	ReqRecord   ProtoRequest
	RespRecord  ProtoResponse
}

func (pm *ProtoMessage) String() string {
	timeMilli := int64(pm.LatencyNano) / (int64(time.Millisecond) / int64(time.Nanosecond))
	return fmt.Sprintf("%s %d ms  %v\n%s\n%s\n",
		pm.SockKey.String(),
		timeMilli,
		time.Unix(0, int64(pm.Timestamp)),
		pm.ReqRecord,
		pm.RespRecord)
}

type ProtoMatcher interface {
	MatchRequest(req *Request) *ProtoMessage
	MatchResponse(resp *Response) *ProtoMessage
}
