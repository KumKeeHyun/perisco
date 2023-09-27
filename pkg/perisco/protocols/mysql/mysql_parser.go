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

var mysqlCommands = map[byte]pb.MySQLCommand{
	0x03: pb.MySQLCommand_COM_QUERY,

	0x01: pb.MySQLCommand_COM_QUIT,
	0x02: pb.MySQLCommand_COM_INIT_DB,
	0x04: pb.MySQLCommand_COM_FIELD_LIST,
	0x07: pb.MySQLCommand_COM_REFRESH,
	0x08: pb.MySQLCommand_COM_STATISTICS,
	0x0A: pb.MySQLCommand_COM_PROCESS_INFO,
	0x0C: pb.MySQLCommand_COM_PROCESS_KILL,
	0x0D: pb.MySQLCommand_COM_DEBUG,
	0x0E: pb.MySQLCommand_COM_PING,
	0x11: pb.MySQLCommand_COM_CHANGE_USER,
	0x1F: pb.MySQLCommand_COM_RESET_CONNECTION,
	0x1A: pb.MySQLCommand_COM_SET_OPTION,

	0x16: pb.MySQLCommand_COM_STMT_PREPARE,
	0x17: pb.MySQLCommand_COM_STMT_EXECUTE,
	// 0x19: pb.MySQLCommand_COM_STMT_FETCH,
	0x19: pb.MySQLCommand_COM_STMT_CLOSE,
	// 0x1A: pb.MySQLCommand_COM_STMT_RESET,
	0x18: pb.MySQLCommand_COM_STMT_SEND_LONG_DATA,
}

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
	header, exists := p.reqHeaders[*sockKey]
	if len(msg) == 4 {
		length := int(uint32(msg[0]) | uint32(msg[1])<<8 | uint32(msg[2])<<16)
		if length > 10_000 {
			// to avoid false positive
			return nil, ErrTooLongPayload
		}

		seq := uint8(msg[3])
		if seq != 0 {
			return nil, nil
		}

		p.reqHeaders[*sockKey] = Header{
			PayloadLength: length,
			SequenceID:    seq,
		}
		return nil, nil
	}

	if exists && (header.PayloadLength > types.MAX_MSG_SIZE || header.PayloadLength == len(msg)) {
		delete(p.reqHeaders, *sockKey)

		command, cmdExists := mysqlCommands[msg[0]]
		if !cmdExists {
			return nil, nil
		}

		return []protocols.ProtoRequest{
			&MySQLRequest{
				PayloadLength: header.PayloadLength,
				Command:       command,
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
	mr := bytes.NewReader(msg)
	lastPacket := MySQLResponse{}
	packetIdx := 0
	headerBuf := []byte{0, 0, 0, 0}

	for mr.Len() > 4 {
		n, err := mr.Read(headerBuf)
		if err != nil || n != 4 {
			break
		}
		packetIdx++
		length := int(uint32(headerBuf[0]) | uint32(headerBuf[1])<<8 | uint32(headerBuf[2])<<16)
		seq := uint8(headerBuf[3])
		if packetIdx == 1 && seq != 1 {
			break
		}

		n, err = mr.Read(p.dataBuf[:length])
		if err != nil {
			break
		}
		respType := pb.MySQLResponseType_UNKNOWN
		if n > 1 {
			switch p.dataBuf[0] {
			case 0x00:
				respType = pb.MySQLResponseType_OK
			case 0xFF:
				respType = pb.MySQLResponseType_ERR
			case 0xFE:
				respType = pb.MySQLResponseType_EOF
			default:
				respType = pb.MySQLResponseType_UNKNOWN
			}
		}

		lastPacket = MySQLResponse{
			Type:         respType,
			AffectedRows: 0,
			ErrorCode:    0,
		}
		if packetIdx == 1 &&
			(respType == pb.MySQLResponseType_OK ||
				respType == pb.MySQLResponseType_ERR) {
			break
		}
	}

	return []protocols.ProtoResponse{
		&MySQLResponse{
			Type:         lastPacket.Type,
			AffectedRows: lastPacket.AffectedRows,
			ErrorCode:    lastPacket.ErrorCode,
		},
	}, nil
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
	PayloadLength int
	Command       pb.MySQLCommand
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
				Command:       r.Command,
			},
		},
	}
}

type MySQLResponse struct {
	Type         pb.MySQLResponseType
	AffectedRows uint64
	ErrorCode    uint16
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
				Type:         r.Type,
				AffectedRows: r.AffectedRows,
				ErrorCode:    uint32(r.ErrorCode),
			},
		},
	}
}
