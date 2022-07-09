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

type MsgEvent struct {
	Msg       [4096]byte
	SockKey   SockKey
	MsgSize   uint32
	Timestamp uint64
	FlowType  FlowType
	Protocol  ProtocolType
}

type IpNetwork struct {
	IpAddr [16]byte
	IpMask [16]byte
}

type IpNetworks struct {
	Data [5]IpNetwork
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

type Ip struct {
	Source      [16]byte
	Destination [16]byte
	IpVersion   IpVersion
}

func (ip *Ip) GetSrcIp() string {
	if ip.IpVersion == IPv4 {
		return net.IP(ip.Source[:4]).String()
	} else if ip.IpVersion == IPv6 {
		return net.IP(ip.Source[:]).String()
	}
	return "unknown"
}

func (ip *Ip) GetDestIp() string {
	if ip.IpVersion == IPv4 {
		return net.IP(ip.Destination[:4]).String()
	} else if ip.IpVersion == IPv6 {
		return net.IP(ip.Destination[:]).String()
	}
	return "unknown"
}

type Layer4Type int32

const (
	LAYER4_UNKNOWN Layer4Type = iota
	TCP
	UDP
)

type Layer4 struct {
	SourcePort      uint32
	DestinationPort uint32
	L4Type          int32
}

type SockKey struct {
	Ip  Ip
	L4  Layer4
	Pid uint32
}

func (sk *SockKey) String() string {
	return fmt.Sprintf("%s %d\t%s %d\t%d",
		sk.Ip.GetSrcIp(),
		sk.L4.SourcePort,
		sk.Ip.GetDestIp(),
		sk.L4.DestinationPort,
		sk.Pid,
	)
}

type EndpointKey struct {
	IpAddr    [16]byte
	IpVersion IpVersion
	Port      uint32
	Pid       uint32
}