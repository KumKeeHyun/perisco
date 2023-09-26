package mysql

import (
	"bytes"
	"errors"

	pb "github.com/KumKeeHyun/perisco/api/v1/perisco"
	"github.com/KumKeeHyun/perisco/pkg/ebpf/types"
	"github.com/KumKeeHyun/perisco/pkg/perisco/protocols"
)

var (
	ErrTooLongPayload = errors.New("too long payload")
	ErrNotMySQLPacket = errors.New("not mysql packet")
)

// MySQLParser should avoid false positives
//
// MySQL packet:
//      0         8        16        24        32
//      +---------+---------+---------+---------+
//      |        payload_length       | seq_id  |
//      +---------+---------+---------+---------+
//      |                                       |
//      .            ...  body ...              .
//      .                                       .
//      .                                       .
//      +----------------------------------------
type MySQLParser struct {
	reqHeaders map[types.SockKey]Header
	dataBuf    [types.MAX_MSG_SIZE]byte
}

var _ protocols.ProtoParser = &MySQLParser{}

func NewMySQLParser() *MySQLParser {
	return &MySQLParser{
		reqHeaders: make(map[types.SockKey]Header, 100),
	}
}

// ParseRequest implements protocols.ProtoParser.
func (p *MySQLParser) ParseRequest(sockKey *types.SockKey, msg []byte) ([]protocols.ProtoRequest, error) {
	// if sockKey.L4.SourcePort == 3306 {
	// 	log.Println("request", msg)
	// }

	header, exists := p.reqHeaders[*sockKey]
	if len(msg) == 4 {
		length := int(uint32(msg[0]) | uint32(msg[1])<<8 | uint32(msg[2])<<16)
		if length > 10_000 {
			// to avoid false positive
			return nil, ErrTooLongPayload
		}
		seq := uint8(msg[3])
		p.reqHeaders[*sockKey] = Header{
			PayloadLength: length,
			SequenceID:    seq,
		}
		return nil, nil
	}

	if exists && header.PayloadLength == len(msg) {
		delete(p.reqHeaders, *sockKey)
		return []protocols.ProtoRequest{
			&MySQLRequest{
				Header: header,
			},
		}, nil
	}

	return nil, ErrNotMySQLPacket
}

func (p *MySQLParser) EnableInferRequest() bool {
	return true
}

// ParseResponse implements protocols.ProtoParser.
func (p *MySQLParser) ParseResponse(sockKey *types.SockKey, msg []byte) ([]protocols.ProtoResponse, error) {
	// if sockKey.L4.SourcePort == 3306 {
	// 	log.Println("response", msg)
	// }

	mr := bytes.NewReader(msg)
	rrs := make([]protocols.ProtoResponse, 0, 5)
	headerBuf := []byte{0, 0, 0, 0}
	for mr.Len() > 4 {
		n, err := mr.Read(headerBuf)
		if err != nil || n != 4 {
			break
		}
		length := int(uint32(headerBuf[0]) | uint32(headerBuf[1])<<8 | uint32(headerBuf[2])<<16)
		seq := uint8(headerBuf[3])

		n, err = mr.Read(p.dataBuf[:length])
		if err != nil {
			break
		}

		rrs = append(rrs, &MySQLResponse{
			Header: Header{length, seq},
		})
	}
	return rrs, nil
}

func (p *MySQLParser) EnableInferResponse() bool {
	// mysql is disabled infer response to prevent false positives
	return false
}

// ProtoType implements protocols.ProtoParser.
func (*MySQLParser) ProtoType() types.ProtocolType {
	return types.MySQL
}

type Header struct {
	PayloadLength int
	SequenceID    uint8
}

type MySQLRequest struct {
	Header
}

var _ protocols.ProtoRequest = &MySQLRequest{}

// ProtoType implements ProtoRequest
func (*MySQLRequest) ProtoType() types.ProtocolType {
	return types.MySQL
}

// Protobuf implements ProtoRequest
func (r *MySQLRequest) Protobuf() *pb.Request {
	return &pb.Request{
		Record: &pb.Request_Mysql{
			Mysql: &pb.MySQLRequest{
				PayloadLength: uint32(r.PayloadLength),
				SequenceId:    uint32(r.SequenceID),
			},
		},
	}
}

type MySQLResponse struct {
	Header
}

var _ protocols.ProtoResponse = &MySQLResponse{}

// ProtoType implements ProtoResponse
func (*MySQLResponse) ProtoType() types.ProtocolType {
	return types.MySQL
}

// Protobuf implements ProtoResponse
func (r *MySQLResponse) Protobuf() *pb.Response {
	return &pb.Response{
		Record: &pb.Response_Mysql{
			Mysql: &pb.MySQLResponse{
				PayloadLength: uint32(r.PayloadLength),
				SequenceId:    uint32(r.SequenceID),
			},
		},
	}
}
