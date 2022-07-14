package bpf

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"

	"github.com/KumKeeHyun/perisco/pkg/ebpf/types"
)

func TestMsgEvent_Serdes(t *testing.T) {
	testMsg := "test MsgEvent serialize/deserialize"

	bpfMsgEvent := bpfMsgEvent{}
	for i, r := range testMsg {
		bpfMsgEvent.Msg[i] = int8(r)
	}
	bpfMsgEvent.MsgSize = uint32(len(testMsg))
	bpfMsgEvent.FlowType = int32(types.FLOW_UNKNOWN)
	bpfMsgEvent.Protocol = int32(types.PROTO_UNKNOWN)

	typesMsgEvent := types.MsgEvent{}
	if err := serDes(&bpfMsgEvent, &typesMsgEvent); err != nil {
		t.Error(err)
		return
	}

	if !bytes.Equal(typesMsgEvent.Bytes(), []byte(testMsg)) {
		t.Errorf("typesMsgEvent.Msg = %v, want = %v", typesMsgEvent.Bytes(), []byte(testMsg))
		return
	}
	if typesMsgEvent.FlowType != types.FLOW_UNKNOWN {
		t.Errorf("typesMsgEvent.FlowType = %v, want = %v", typesMsgEvent.FlowType, types.FLOW_UNKNOWN)
		return
	}
	if typesMsgEvent.Protocol != types.PROTO_UNKNOWN {
		t.Errorf("typesMsgEvent.Protocol = %v, want = %v", typesMsgEvent.Protocol, types.PROTO_UNKNOWN)
		return
	}
}

func serDes(src, dst interface{}) error {
	buf := bytes.NewBuffer([]byte{})
	if err := binary.Write(buf, binary.LittleEndian, src); err != nil {
		return err
	}
	if err := binary.Read(buf, binary.LittleEndian, dst); err != nil {
		return err
	}
	return nil
}

func TestSockKey_Serdes(t *testing.T) {
	testIp := net.ParseIP("::ffff:127.0.0.1")
	testPort := uint32(8080)
	testPid := uint32(1234)

	bpfSockKey := bpfSockKey{}
	for i, b := range testIp {
		bpfSockKey.Ip.Source[i] = int8(b)
		bpfSockKey.Ip.Destination[i] = int8(b)
	}
	bpfSockKey.Ip.IpVersion = int32(types.IPv6)
	bpfSockKey.L4.SourcePort = testPort
	bpfSockKey.L4.DestinationPort = testPort
	bpfSockKey.L4.L4Type = int32(types.TCP)
	bpfSockKey.Pid = testPid

	typesSockKey := types.SockKey{}
	if err := serDes(&bpfSockKey, &typesSockKey); err != nil {
		t.Error(err)
		return
	}

	if !bytes.Equal(typesSockKey.Ip.Source[:], testIp) {
		t.Errorf("typesSockKey.Ip.Source = %v, want = %v", typesSockKey.Ip.Source, testIp)
		return
	}
	if !bytes.Equal(typesSockKey.Ip.Destination[:], testIp) {
		t.Errorf("typesSockKey.Ip.Destination = %v, want = %v", typesSockKey.Ip.Destination, testIp)
		return
	}
	if typesSockKey.Ip.IpVersion != types.IPv6 {
		t.Errorf("typesSockKey.Ip.IpVersion = %v, want = %v", typesSockKey.Ip.IpVersion, types.IPv6)
		return
	}

	if typesSockKey.L4.SourcePort != testPort ||
		typesSockKey.L4.DestinationPort != testPort ||
		typesSockKey.L4.L4Type != types.TCP {
		t.Errorf("typesSockKey.L4 = %v, want = %v", typesSockKey.L4,
			types.Layer4{SourcePort: testPort, DestinationPort: testPort, L4Type: types.TCP})
		return
	}

	if typesSockKey.Pid != testPid {
		t.Errorf("typesSockKey.Pid = %v, want = %v", typesSockKey.Pid, testPid)
		return
	}
}

func TestEndpointKey_Serdes(t *testing.T) {
	testIp := net.ParseIP("::ffff:127.0.0.1")
	testPort := uint32(8080)
	testPid := uint32(1234)

	bpfEndpointKey := bpfEndpointKey{}
	for i, b := range testIp {
		bpfEndpointKey.IpAddr[i] = int8(b)
	}
	bpfEndpointKey.IpVersion = int32(types.IPv6)
	bpfEndpointKey.Port = testPort
	bpfEndpointKey.Pid = testPid

	typesEndpointKey := types.EndpointKey{}
	if err := serDes(&bpfEndpointKey, &typesEndpointKey); err != nil {
		t.Error(err)
		return
	}

	if !bytes.Equal(typesEndpointKey.IpAddr[:], testIp) {
		t.Errorf("typesEndpointKey.IpAddr = %v, want = %v", typesEndpointKey.IpAddr, testIp)
		return
	}
	if typesEndpointKey.IpVersion != types.IPv6 {
		t.Errorf("typesEndpointKey.IpVersion = %v, want = %v", typesEndpointKey.IpVersion, types.IPv6)
		return
	}
	if typesEndpointKey.Port != testPort {
		t.Errorf("typesEndpointKey.Port = %v, want = %v", typesEndpointKey.Port, testPort)
		return
	}
	if typesEndpointKey.Pid != testPid {
		t.Errorf("typesEndpointKey.Pid = %v, want = %v", typesEndpointKey.Pid, testPid)
		return
	}
}

func TestIpNetwork_Serdes(t *testing.T) {
	_, testIpNet, err := net.ParseCIDR("::ffff:127.0.0.1/96")
	if err != nil {
		t.Error(err)
		return
	}

	bpfIpNetwork := bpfIpNetwork{}
	for i, b := range testIpNet.IP {
		bpfIpNetwork.IpAddr[i] = int8(b)
	}
	for i, b := range testIpNet.Mask {
		bpfIpNetwork.IpMask[i] = int8(b)
	}

	typesIpNetwork := types.IpNetwork{}
	if err := serDes(&bpfIpNetwork, &typesIpNetwork); err != nil {
		t.Error(err)
		return
	}

	if !bytes.Equal(typesIpNetwork.IpAddr[:], testIpNet.IP) {
		t.Errorf("typesIpNetwork.IpAddr = %v, want = %v", typesIpNetwork.IpAddr, testIpNet.IP)
		return
	}
	if !bytes.Equal(typesIpNetwork.IpMask[:], testIpNet.Mask) {
		t.Errorf("typesIpNetwork.IpMask = %v, want = %v", typesIpNetwork.IpMask, testIpNet.Mask)
		return
	}
}


func TestIpNetworks_Serdes(t *testing.T) {
	_, testIpNet, err := net.ParseCIDR("::ffff:127.0.0.1/96")
	if err != nil {
		t.Error(err)
		return
	}

	bpfIpNetworks := bpfIpNetworks{}
	for i, b := range testIpNet.IP {
		bpfIpNetworks.Data[0].IpAddr[i] = int8(b)
	}
	for i, b := range testIpNet.Mask {
		bpfIpNetworks.Data[0].IpMask[i] = int8(b)
	}
	bpfIpNetworks.Size = 1

	typesIpNetworks := types.IpNetworks{}
	if err := serDes(&bpfIpNetworks, &typesIpNetworks); err != nil {
		t.Error(err)
		return
	}

	if typesIpNetworks.Size != 1 {
		t.Errorf("typesIpNetworks.Size = %v, want = %v", typesIpNetworks.Size, 1)
		return
	}
	if !bytes.Equal(typesIpNetworks.Data[0].IpAddr[:], testIpNet.IP) {
		t.Errorf("typesIpNetworks.Data[0].IpAddr = %v, want = %v", typesIpNetworks.Data[0].IpAddr, testIpNet.IP)
		return
	}
	if !bytes.Equal(typesIpNetworks.Data[0].IpMask[:], testIpNet.Mask) {
		t.Errorf("typesIpNetworks.Data[0].IpMask = %v, want = %v", typesIpNetworks.Data[0].IpMask, testIpNet.Mask)
		return
	}
}