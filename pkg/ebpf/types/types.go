package types

import (
	"fmt"
	"net"
)

const MAX_MSG_SIZE = 4096

type MsgEvent struct {
	Msg       [MAX_MSG_SIZE]byte
	SockKey   SockKey
	MsgSize   uint32
	Timestamp uint64
	FlowType  FlowType
	Protocol  ProtocolType
}

func (msg *MsgEvent) Bytes() []byte {
	len := msg.MsgSize
	if len > MAX_MSG_SIZE {
		len = MAX_MSG_SIZE
	}
	return msg.Msg[:len]
}

type SockKey struct {
	Ip  Ip
	L4  Layer4
	Pid uint32
}

func (sk *SockKey) String() string {
	return fmt.Sprintf("%s:%d  %s:%d  %s/%s  pid:%d",
		sk.Ip.GetSrcIp(),
		sk.L4.SourcePort,
		sk.Ip.GetDestIp(),
		sk.L4.DestinationPort,
		sk.Ip.IpVersion.String(),
		sk.L4.L4Type.String(),
		sk.Pid,
	)
}

func (sk *SockKey) ToEndpointKey() EndpointKey {
	return EndpointKey{
		IpAddr:    sk.Ip.Source,
		IpVersion: sk.Ip.IpVersion,
		Port:      sk.L4.SourcePort,
		Pid:       sk.Pid,
	}
}

type EndpointKey struct {
	IpAddr    [16]byte
	IpVersion IpVersion
	Port      uint32
	Pid       uint32
}

type IpVersion int32

const (
	IP_UNKNOWN IpVersion = iota
	IPv4
	IPv6
)

var IpVersionName = map[IpVersion]string{
	IP_UNKNOWN: "UNKNOWN",
	IPv4:       "IPv4",
	IPv6:       "IPv6",
}

func (i IpVersion) String() string {
	if name, exist := IpVersionName[i]; exist {
		return name
	}
	return "UNKNOWN"
}

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

var Layer4TypeName = map[Layer4Type]string{
	LAYER4_UNKNOWN: "UNKNOWN",
	TCP:            "TCP",
	UDP:            "UDP",
}

func (l Layer4Type) String() string {
	if name, exist := Layer4TypeName[l]; exist {
		return name
	}
	return "UNKNOWN"
}

type Layer4 struct {
	SourcePort      uint32
	DestinationPort uint32
	L4Type          Layer4Type
}

type FlowType int32

const (
	FLOW_UNKNOWN FlowType = iota
	REQUEST
	RESPONSE
)

var FlowTypeName = map[FlowType]string{
	FLOW_UNKNOWN: "UNKNOWN",
	REQUEST:      "REQUEST",
	RESPONSE:     "RESPONSE",
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

var ProtocolTypeName = map[ProtocolType]string{
	PROTO_UNKNOWN: "UNKNOWN",
	HTTP1:         "HTTP/1.1",
	HTTP2:         "HTTP/2",
}

func (p ProtocolType) String() string {
	if name, exist := ProtocolTypeName[p]; exist {
		return name
	}
	return "UNKNOWN"
}

type IpNetwork struct {
	IpAddr [16]byte
	IpMask [16]byte
}

func ParseCIDR(cidr string) (in IpNetwork, err error) {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return in, err
	}

	copy(in.IpAddr[:], ipNet.IP)
	copy(in.IpMask[:], ipNet.Mask)
	return in, nil
}

const MAX_NET_FILTER_SIZE = 5

type IpNetworks struct {
	Data [MAX_NET_FILTER_SIZE]IpNetwork
	Size uint32
}

func ParseCIDRs(cidrs []string) (IpNetworks, error) {
	if len(cidrs) > MAX_NET_FILTER_SIZE {
		return IpNetworks{}, fmt.Errorf("max network filter size is %d, got = %d",
			MAX_NET_FILTER_SIZE, len(cidrs),
		)
	}

	ins := IpNetworks{Size: uint32(len(cidrs))}
	for i, cidr := range cidrs {
		in, err := ParseCIDR(cidr)
		if err != nil {
			return IpNetworks{}, fmt.Errorf("failed to ParseCIDR: %v", err)
		}
		ins.Data[i] = in
	}
	return ins, nil
}
