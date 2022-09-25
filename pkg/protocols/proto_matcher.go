package protocols

import (
	"fmt"
	"time"

	pb "github.com/KumKeeHyun/perisco/api/v1/perisco"
	"github.com/KumKeeHyun/perisco/pkg/ebpf/types"
	tspb "google.golang.org/protobuf/types/known/timestamppb"
)

type ProtoMessage struct {
	SockKey     types.SockKey
	Timestamp   uint64
	LatencyNano uint64
	ReqRecord   ProtoRequest
	RespRecord  ProtoResponse
}

func (pm *ProtoMessage) Protobuf() *pb.ProtoMessage {
	return &pb.ProtoMessage{
		Ts: tspb.New(time.Unix(0, int64(pm.Timestamp))),
		Pid: pm.SockKey.Pid,
		Ip: pm.SockKey.Ip.Protobuf(),
		L4: pm.SockKey.L4.Protobuf(), 
		L7: &pb.Layer7{
			LatencyNs: pm.LatencyNano,
			Request: pm.ReqRecord.Protobuf(),
			Response: pm.RespRecord.Protobuf(),
		},
	}
}

func (pm *ProtoMessage) String() string {
	timeMilli := int64(pm.LatencyNano) / (int64(time.Millisecond) / int64(time.Nanosecond))
	return fmt.Sprintf("%s %d ms\n%s\n%s\n",
		pm.SockKey.String(),
		timeMilli,
		pm.ReqRecord,
		pm.RespRecord)
}

type ProtoMatcher interface {
	MatchRequest(req *Request) *ProtoMessage
	MatchResponse(resp *Response) *ProtoMessage
}
