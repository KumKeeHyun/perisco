package protocols

import (
	"time"

	pb "github.com/KumKeeHyun/perisco/api/v1/perisco"
	"github.com/KumKeeHyun/perisco/pkg/ebpf/types"
	tspb "google.golang.org/protobuf/types/known/timestamppb"
)

type Request struct {
	Timestamp uint64
	SockKey   types.SockKey
	Record    ProtoRequest
}

type Response struct {
	Timestamp uint64
	SockKey   types.SockKey
	Record    ProtoResponse
}

func ProtoMessage(req *Request, resp *Response) *pb.ProtoMessage {
	return &pb.ProtoMessage{
		Ts:  tspb.New(time.Unix(0, int64(req.Timestamp))),
		Pid: req.SockKey.Pid,
		Ip:  req.SockKey.Ip.Protobuf(),
		L4:  req.SockKey.L4.Protobuf(),
		L7: &pb.Layer7{
			LatencyNs: resp.Timestamp - req.Timestamp,
			Request:   req.Record.Protobuf(),
			Response:  resp.Record.Protobuf(),
		},
	}
}

type ProtoMatcher interface {
	MatchRequest(req *Request) *pb.ProtoMessage
	MatchResponse(resp *Response) *pb.ProtoMessage
}
