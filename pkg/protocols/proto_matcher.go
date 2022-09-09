package protocols

import (
	"fmt"
	"time"

	"github.com/KumKeeHyun/perisco/pkg/ebpf/types"
)

type ProtoMessage struct {
	SockKey types.SockKey
	Time    uint64
	Req     RequestRecord
	Resp    ResponseRecord
}

func (pm *ProtoMessage) String() string {
	timeMilli := int64(pm.Time) / (int64(time.Millisecond) / int64(time.Nanosecond))
	return fmt.Sprintf("%s %d ms\n%s\n%s\n",
		pm.SockKey.String(),
		timeMilli,
		pm.Req,
		pm.Resp)
}

type ProtoMatcher interface {
	MatchRequest(req *Request) (*ProtoMessage, error)
	MatchResponse(resp *Response) (*ProtoMessage, error)
}
