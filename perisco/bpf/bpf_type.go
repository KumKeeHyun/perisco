package bpf

import (
	"fmt"
	"net"
)

type FlowType int32

const (
	FLOW_UNKNOWN FlowType = iota
	REQUEST
	RESPONSE
)

var FlowTypeName = map[FlowType]string {
	FLOW_UNKNOWN: "UNKNOWN",
	REQUEST: "REQUEST",
	RESPONSE: "RESPONSE",
}

func (f FlowType) String() string {
	if name, exist := FlowTypeName[f]; exist {
		return name
	} 
	return "UNKNOWN"
}

type ProtocolType int32

const (
	PROTO_UNKNOWN ProtocolType = iota
	PROTO_SKIP

	HTTP1
	HTTP2

	PROTO_RESERVED1
	PROTO_RESERVED2
	PROTO_RESERVED3
	PROTO_RESERVED4
	PROTO_RESERVED5
)

var ProtocolTypeName = map[ProtocolType]string {
	PROTO_UNKNOWN: "UNKNOWN",
	HTTP1: "HTTP/1.1",
	HTTP2: "HTTP/2",
}

func (p ProtocolType) String() string {
	if name, exist := ProtocolTypeName[p]; exist {
		return name
	} 
	return "UNKNOWN"
}

type BpfDataEvent struct {
	Msg       [4096]byte
	SockKey   BpfSockKey
	Timestamp uint64
	FlowType  FlowType
	Protocol  ProtocolType
	MsgSize   uint32
	_         [4]byte
}

type BpfIpNetwork struct {
	IpAddr [16]byte
	IpMask [16]byte
}

type BpfIpNetworks struct {
	Data [5]BpfIpNetwork
	Size uint32
}

const MAX_NET_FILTER_SIZE = 5
var	NET_FILTER_KEY uint32 = 0



type IpVersion int32

const (
	IP_UNKNOWN IpVersion = iota
	IPv4
	IPv6
)

type BpfIp struct {
	Source      [16]byte
	Destination [16]byte
	IpVersion   IpVersion
}

func (ip *BpfIp) GetSrcIp() string {
	if ip.IpVersion == IPv4 {
		return net.IP(ip.Source[:4]).String()
	} else if ip.IpVersion == IPv6 {
		return net.IP(ip.Source[:]).String()
	}
	return "unknown"
}

func (ip *BpfIp) GetDestIp() string {
	if ip.IpVersion == IPv4 {
		return net.IP(ip.Destination[:4]).String()
	} else if ip.IpVersion == IPv6 {
		return net.IP(ip.Destination[:]).String()
	}
	return "unknown"
}

type BpfLayer4 struct {
	SourcePort      uint32
	DestinationPort uint32
}

type BpfSockKey struct {
	Ip  BpfIp
	L4  BpfLayer4
	Pid uint32
}

func (sk *BpfSockKey) String() string {
	return fmt.Sprintf("%-15s %-6d  %-15s %-6d  %-10d",
		sk.Ip.GetSrcIp(),
		sk.L4.SourcePort,
		sk.Ip.GetDestIp(),
		sk.L4.DestinationPort,
		sk.Pid,
	)
}
