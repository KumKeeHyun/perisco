package bpf

import (
	"encoding/binary"
	"net"
)

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
	SockKey   BpfSockKey
	SendBytes uint64
	RecvBytes uint64
}

type BpfConnEvent struct {
	SockKey BpfSockKey
}

type BpfDataEvent struct {
	Msg       [4096]byte
	SockKey   BpfSockKey
	MsgType   int32
	ProtoType int32
	MsgSize   uint32
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
	Pid    uint32
	Family uint8
	Pad1   uint8
	Pad2   uint16
}

func (sk *BpfSockKey) GetSrcIpv4() string {
	if sk.Family == 2 {
		return intToIP(sk.Sip.Addr.Pad1).String()
	} else if sk.Family == 10 {
		return intToIPv6(sk.Sip.Addr.Pad1, sk.Sip.Addr.Pad2, sk.Sip.Addr.Pad3, sk.Sip.Addr.Pad4).String()
	}
	return "unknown"
}

func (sk *BpfSockKey) GetDstIpv4() string {
	if sk.Family == 2 {
		return intToIP(sk.Dip.Addr.Pad1).String()
	} else if sk.Family == 10 {
		return intToIPv6(sk.Dip.Addr.Pad1, sk.Dip.Addr.Pad2, sk.Dip.Addr.Pad3, sk.Dip.Addr.Pad4).String()
	}
	return "unknown"
}

// intToIP converts IPv4 number to net.IP
func intToIP(ipNum uint32) net.IP {
	ip := make(net.IP, 4)
	binary.LittleEndian.PutUint32(ip, ipNum)
	return ip
}

func intToIPv6(p1, p2, p3, p4 uint32) net.IP {
	ip := make(net.IP, 16)
	binary.LittleEndian.PutUint32(ip[:4], p1)
	binary.LittleEndian.PutUint32(ip[4:8], p2)
	binary.LittleEndian.PutUint32(ip[8:12], p3)
	binary.LittleEndian.PutUint32(ip[12:], p4)
	return ip
}
