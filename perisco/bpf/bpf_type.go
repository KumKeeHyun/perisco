package bpf

import (
	"encoding/binary"
	"net"
)

func IntToEndpointRole(roleNum int32) string {
	switch roleNum {
	case 0:
		return "CLIENT"
	case 1:
		return "SERVER"
	default:
		return "UNKNOWN"
	}
}

func IntToMsgType(msgType int32) string {
	switch msgType {
	case 0:
		return "REQUEST"
	case 1:
		return "RESPONSE"
	default:
		return "UNKNOWN"
	}
}

type BpfCloseEvent struct {
	SockKey      BpfSockKey
	EndpointRole int32
	SendBytes    uint64
	RecvBytes    uint64
}

type BpfConnEvent struct {
	SockKey      BpfSockKey
	EndpointRole int32
}

type BpfDataEvent struct {
	SockKey      BpfSockKey
	EndpointRole int32
	MsgType      int32
	_            [4]byte
	MsgSize      uint64
	NrSegs       uint64
	Count        uint32
	Offset       uint32
	Msg          [4096]byte
}

type BpfSockKey struct {
	Sip struct {
		Addr struct {
			Pad1 uint32
			Pad2 uint32
			Pad3 uint32
			Pad4 uint32
		}
	}
	Dip struct {
		Addr struct {
			Pad1 uint32
			Pad2 uint32
			Pad3 uint32
			Pad4 uint32
		}
	}
	Sport  uint32
	Dport  uint32
	Family uint8
	Pad1   uint8
	Pad2   uint16
}

func (sk *BpfSockKey) GetSrcIpv4() net.IP {
	return intToIP(sk.Sip.Addr.Pad1)
}

func (sk *BpfSockKey) GetDstIpv4() net.IP {
	return intToIP(sk.Dip.Addr.Pad1)
}

// intToIP converts IPv4 number to net.IP
func intToIP(ipNum uint32) net.IP {
	ip := make(net.IP, 4)
	binary.LittleEndian.PutUint32(ip, ipNum)
	return ip
}
