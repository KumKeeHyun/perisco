// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.28.1
// 	protoc        v3.21.6
// source: perisco.proto

package perisco

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	timestamppb "google.golang.org/protobuf/types/known/timestamppb"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type IPVersion int32

const (
	IPVersion_IP_UNKNOWN IPVersion = 0
	IPVersion_IPv4       IPVersion = 1
	IPVersion_IPv6       IPVersion = 2
)

// Enum value maps for IPVersion.
var (
	IPVersion_name = map[int32]string{
		0: "IP_UNKNOWN",
		1: "IPv4",
		2: "IPv6",
	}
	IPVersion_value = map[string]int32{
		"IP_UNKNOWN": 0,
		"IPv4":       1,
		"IPv6":       2,
	}
)

func (x IPVersion) Enum() *IPVersion {
	p := new(IPVersion)
	*p = x
	return p
}

func (x IPVersion) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (IPVersion) Descriptor() protoreflect.EnumDescriptor {
	return file_perisco_proto_enumTypes[0].Descriptor()
}

func (IPVersion) Type() protoreflect.EnumType {
	return &file_perisco_proto_enumTypes[0]
}

func (x IPVersion) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use IPVersion.Descriptor instead.
func (IPVersion) EnumDescriptor() ([]byte, []int) {
	return file_perisco_proto_rawDescGZIP(), []int{0}
}

type ProtoMessage struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Ts  *timestamppb.Timestamp `protobuf:"bytes,1,opt,name=ts,proto3" json:"ts,omitempty"`
	Pid uint32                 `protobuf:"varint,2,opt,name=pid,proto3" json:"pid,omitempty"`
	Ip  *IP                    `protobuf:"bytes,3,opt,name=ip,proto3" json:"ip,omitempty"`
	L4  *Layer4                `protobuf:"bytes,4,opt,name=l4,proto3" json:"l4,omitempty"`
	L7  *Layer7                `protobuf:"bytes,5,opt,name=l7,proto3" json:"l7,omitempty"`
}

func (x *ProtoMessage) Reset() {
	*x = ProtoMessage{}
	if protoimpl.UnsafeEnabled {
		mi := &file_perisco_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ProtoMessage) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ProtoMessage) ProtoMessage() {}

func (x *ProtoMessage) ProtoReflect() protoreflect.Message {
	mi := &file_perisco_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ProtoMessage.ProtoReflect.Descriptor instead.
func (*ProtoMessage) Descriptor() ([]byte, []int) {
	return file_perisco_proto_rawDescGZIP(), []int{0}
}

func (x *ProtoMessage) GetTs() *timestamppb.Timestamp {
	if x != nil {
		return x.Ts
	}
	return nil
}

func (x *ProtoMessage) GetPid() uint32 {
	if x != nil {
		return x.Pid
	}
	return 0
}

func (x *ProtoMessage) GetIp() *IP {
	if x != nil {
		return x.Ip
	}
	return nil
}

func (x *ProtoMessage) GetL4() *Layer4 {
	if x != nil {
		return x.L4
	}
	return nil
}

func (x *ProtoMessage) GetL7() *Layer7 {
	if x != nil {
		return x.L7
	}
	return nil
}

type IP struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Client    string    `protobuf:"bytes,1,opt,name=client,proto3" json:"client,omitempty"`
	Server    string    `protobuf:"bytes,2,opt,name=server,proto3" json:"server,omitempty"`
	IpVersion IPVersion `protobuf:"varint,3,opt,name=ipVersion,proto3,enum=perisco.IPVersion" json:"ipVersion,omitempty"`
}

func (x *IP) Reset() {
	*x = IP{}
	if protoimpl.UnsafeEnabled {
		mi := &file_perisco_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *IP) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*IP) ProtoMessage() {}

func (x *IP) ProtoReflect() protoreflect.Message {
	mi := &file_perisco_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use IP.ProtoReflect.Descriptor instead.
func (*IP) Descriptor() ([]byte, []int) {
	return file_perisco_proto_rawDescGZIP(), []int{1}
}

func (x *IP) GetClient() string {
	if x != nil {
		return x.Client
	}
	return ""
}

func (x *IP) GetServer() string {
	if x != nil {
		return x.Server
	}
	return ""
}

func (x *IP) GetIpVersion() IPVersion {
	if x != nil {
		return x.IpVersion
	}
	return IPVersion_IP_UNKNOWN
}

type Layer4 struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Types that are assignable to Protocol:
	//	*Layer4_TCP
	//	*Layer4_UDP
	Protocol isLayer4_Protocol `protobuf_oneof:"protocol"`
}

func (x *Layer4) Reset() {
	*x = Layer4{}
	if protoimpl.UnsafeEnabled {
		mi := &file_perisco_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Layer4) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Layer4) ProtoMessage() {}

func (x *Layer4) ProtoReflect() protoreflect.Message {
	mi := &file_perisco_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Layer4.ProtoReflect.Descriptor instead.
func (*Layer4) Descriptor() ([]byte, []int) {
	return file_perisco_proto_rawDescGZIP(), []int{2}
}

func (m *Layer4) GetProtocol() isLayer4_Protocol {
	if m != nil {
		return m.Protocol
	}
	return nil
}

func (x *Layer4) GetTCP() *TCP {
	if x, ok := x.GetProtocol().(*Layer4_TCP); ok {
		return x.TCP
	}
	return nil
}

func (x *Layer4) GetUDP() *UDP {
	if x, ok := x.GetProtocol().(*Layer4_UDP); ok {
		return x.UDP
	}
	return nil
}

type isLayer4_Protocol interface {
	isLayer4_Protocol()
}

type Layer4_TCP struct {
	TCP *TCP `protobuf:"bytes,1,opt,name=TCP,proto3,oneof"`
}

type Layer4_UDP struct {
	UDP *UDP `protobuf:"bytes,2,opt,name=UDP,proto3,oneof"`
}

func (*Layer4_TCP) isLayer4_Protocol() {}

func (*Layer4_UDP) isLayer4_Protocol() {}

type TCP struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	ClientPort uint32 `protobuf:"varint,1,opt,name=client_port,json=clientPort,proto3" json:"client_port,omitempty"`
	ServerPort uint32 `protobuf:"varint,2,opt,name=server_port,json=serverPort,proto3" json:"server_port,omitempty"`
}

func (x *TCP) Reset() {
	*x = TCP{}
	if protoimpl.UnsafeEnabled {
		mi := &file_perisco_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *TCP) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*TCP) ProtoMessage() {}

func (x *TCP) ProtoReflect() protoreflect.Message {
	mi := &file_perisco_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use TCP.ProtoReflect.Descriptor instead.
func (*TCP) Descriptor() ([]byte, []int) {
	return file_perisco_proto_rawDescGZIP(), []int{3}
}

func (x *TCP) GetClientPort() uint32 {
	if x != nil {
		return x.ClientPort
	}
	return 0
}

func (x *TCP) GetServerPort() uint32 {
	if x != nil {
		return x.ServerPort
	}
	return 0
}

type UDP struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	ClientPort uint32 `protobuf:"varint,1,opt,name=client_port,json=clientPort,proto3" json:"client_port,omitempty"`
	ServerPort uint32 `protobuf:"varint,2,opt,name=server_port,json=serverPort,proto3" json:"server_port,omitempty"`
}

func (x *UDP) Reset() {
	*x = UDP{}
	if protoimpl.UnsafeEnabled {
		mi := &file_perisco_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *UDP) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*UDP) ProtoMessage() {}

func (x *UDP) ProtoReflect() protoreflect.Message {
	mi := &file_perisco_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use UDP.ProtoReflect.Descriptor instead.
func (*UDP) Descriptor() ([]byte, []int) {
	return file_perisco_proto_rawDescGZIP(), []int{4}
}

func (x *UDP) GetClientPort() uint32 {
	if x != nil {
		return x.ClientPort
	}
	return 0
}

func (x *UDP) GetServerPort() uint32 {
	if x != nil {
		return x.ServerPort
	}
	return 0
}

type Layer7 struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	LatencyNs uint64    `protobuf:"varint,1,opt,name=latency_ns,json=latencyNs,proto3" json:"latency_ns,omitempty"`
	Request   *Request  `protobuf:"bytes,2,opt,name=request,proto3" json:"request,omitempty"`
	Response  *Response `protobuf:"bytes,3,opt,name=response,proto3" json:"response,omitempty"`
}

func (x *Layer7) Reset() {
	*x = Layer7{}
	if protoimpl.UnsafeEnabled {
		mi := &file_perisco_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Layer7) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Layer7) ProtoMessage() {}

func (x *Layer7) ProtoReflect() protoreflect.Message {
	mi := &file_perisco_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Layer7.ProtoReflect.Descriptor instead.
func (*Layer7) Descriptor() ([]byte, []int) {
	return file_perisco_proto_rawDescGZIP(), []int{5}
}

func (x *Layer7) GetLatencyNs() uint64 {
	if x != nil {
		return x.LatencyNs
	}
	return 0
}

func (x *Layer7) GetRequest() *Request {
	if x != nil {
		return x.Request
	}
	return nil
}

func (x *Layer7) GetResponse() *Response {
	if x != nil {
		return x.Response
	}
	return nil
}

type Request struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Types that are assignable to Record:
	//	*Request_Http
	Record isRequest_Record `protobuf_oneof:"record"`
}

func (x *Request) Reset() {
	*x = Request{}
	if protoimpl.UnsafeEnabled {
		mi := &file_perisco_proto_msgTypes[6]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Request) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Request) ProtoMessage() {}

func (x *Request) ProtoReflect() protoreflect.Message {
	mi := &file_perisco_proto_msgTypes[6]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Request.ProtoReflect.Descriptor instead.
func (*Request) Descriptor() ([]byte, []int) {
	return file_perisco_proto_rawDescGZIP(), []int{6}
}

func (m *Request) GetRecord() isRequest_Record {
	if m != nil {
		return m.Record
	}
	return nil
}

func (x *Request) GetHttp() *HTTPRequest {
	if x, ok := x.GetRecord().(*Request_Http); ok {
		return x.Http
	}
	return nil
}

type isRequest_Record interface {
	isRequest_Record()
}

type Request_Http struct {
	Http *HTTPRequest `protobuf:"bytes,1,opt,name=http,proto3,oneof"`
}

func (*Request_Http) isRequest_Record() {}

type Response struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Types that are assignable to Record:
	//	*Response_Http
	Record isResponse_Record `protobuf_oneof:"record"`
}

func (x *Response) Reset() {
	*x = Response{}
	if protoimpl.UnsafeEnabled {
		mi := &file_perisco_proto_msgTypes[7]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Response) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Response) ProtoMessage() {}

func (x *Response) ProtoReflect() protoreflect.Message {
	mi := &file_perisco_proto_msgTypes[7]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Response.ProtoReflect.Descriptor instead.
func (*Response) Descriptor() ([]byte, []int) {
	return file_perisco_proto_rawDescGZIP(), []int{7}
}

func (m *Response) GetRecord() isResponse_Record {
	if m != nil {
		return m.Record
	}
	return nil
}

func (x *Response) GetHttp() *HTTPResponse {
	if x, ok := x.GetRecord().(*Response_Http); ok {
		return x.Http
	}
	return nil
}

type isResponse_Record interface {
	isResponse_Record()
}

type Response_Http struct {
	Http *HTTPResponse `protobuf:"bytes,1,opt,name=http,proto3,oneof"`
}

func (*Response_Http) isResponse_Record() {}

type HTTPRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Protocol string        `protobuf:"bytes,1,opt,name=protocol,proto3" json:"protocol,omitempty"`
	Method   string        `protobuf:"bytes,2,opt,name=method,proto3" json:"method,omitempty"`
	Url      string        `protobuf:"bytes,3,opt,name=url,proto3" json:"url,omitempty"`
	Headers  []*HTTPHeader `protobuf:"bytes,4,rep,name=headers,proto3" json:"headers,omitempty"`
}

func (x *HTTPRequest) Reset() {
	*x = HTTPRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_perisco_proto_msgTypes[8]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *HTTPRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*HTTPRequest) ProtoMessage() {}

func (x *HTTPRequest) ProtoReflect() protoreflect.Message {
	mi := &file_perisco_proto_msgTypes[8]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use HTTPRequest.ProtoReflect.Descriptor instead.
func (*HTTPRequest) Descriptor() ([]byte, []int) {
	return file_perisco_proto_rawDescGZIP(), []int{8}
}

func (x *HTTPRequest) GetProtocol() string {
	if x != nil {
		return x.Protocol
	}
	return ""
}

func (x *HTTPRequest) GetMethod() string {
	if x != nil {
		return x.Method
	}
	return ""
}

func (x *HTTPRequest) GetUrl() string {
	if x != nil {
		return x.Url
	}
	return ""
}

func (x *HTTPRequest) GetHeaders() []*HTTPHeader {
	if x != nil {
		return x.Headers
	}
	return nil
}

type HTTPResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Protocol string        `protobuf:"bytes,1,opt,name=protocol,proto3" json:"protocol,omitempty"`
	Code     uint32        `protobuf:"varint,5,opt,name=code,proto3" json:"code,omitempty"`
	Headers  []*HTTPHeader `protobuf:"bytes,7,rep,name=headers,proto3" json:"headers,omitempty"`
}

func (x *HTTPResponse) Reset() {
	*x = HTTPResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_perisco_proto_msgTypes[9]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *HTTPResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*HTTPResponse) ProtoMessage() {}

func (x *HTTPResponse) ProtoReflect() protoreflect.Message {
	mi := &file_perisco_proto_msgTypes[9]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use HTTPResponse.ProtoReflect.Descriptor instead.
func (*HTTPResponse) Descriptor() ([]byte, []int) {
	return file_perisco_proto_rawDescGZIP(), []int{9}
}

func (x *HTTPResponse) GetProtocol() string {
	if x != nil {
		return x.Protocol
	}
	return ""
}

func (x *HTTPResponse) GetCode() uint32 {
	if x != nil {
		return x.Code
	}
	return 0
}

func (x *HTTPResponse) GetHeaders() []*HTTPHeader {
	if x != nil {
		return x.Headers
	}
	return nil
}

type HTTPHeader struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Key   string `protobuf:"bytes,1,opt,name=key,proto3" json:"key,omitempty"`
	Value string `protobuf:"bytes,2,opt,name=value,proto3" json:"value,omitempty"`
}

func (x *HTTPHeader) Reset() {
	*x = HTTPHeader{}
	if protoimpl.UnsafeEnabled {
		mi := &file_perisco_proto_msgTypes[10]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *HTTPHeader) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*HTTPHeader) ProtoMessage() {}

func (x *HTTPHeader) ProtoReflect() protoreflect.Message {
	mi := &file_perisco_proto_msgTypes[10]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use HTTPHeader.ProtoReflect.Descriptor instead.
func (*HTTPHeader) Descriptor() ([]byte, []int) {
	return file_perisco_proto_rawDescGZIP(), []int{10}
}

func (x *HTTPHeader) GetKey() string {
	if x != nil {
		return x.Key
	}
	return ""
}

func (x *HTTPHeader) GetValue() string {
	if x != nil {
		return x.Value
	}
	return ""
}

var File_perisco_proto protoreflect.FileDescriptor

var file_perisco_proto_rawDesc = []byte{
	0x0a, 0x0d, 0x70, 0x65, 0x72, 0x69, 0x73, 0x63, 0x6f, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12,
	0x07, 0x70, 0x65, 0x72, 0x69, 0x73, 0x63, 0x6f, 0x1a, 0x1f, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65,
	0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f, 0x74, 0x69, 0x6d, 0x65, 0x73, 0x74,
	0x61, 0x6d, 0x70, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0xab, 0x01, 0x0a, 0x0c, 0x50, 0x72,
	0x6f, 0x74, 0x6f, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x12, 0x2a, 0x0a, 0x02, 0x74, 0x73,
	0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1a, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61,
	0x6d, 0x70, 0x52, 0x02, 0x74, 0x73, 0x12, 0x10, 0x0a, 0x03, 0x70, 0x69, 0x64, 0x18, 0x02, 0x20,
	0x01, 0x28, 0x0d, 0x52, 0x03, 0x70, 0x69, 0x64, 0x12, 0x1b, 0x0a, 0x02, 0x69, 0x70, 0x18, 0x03,
	0x20, 0x01, 0x28, 0x0b, 0x32, 0x0b, 0x2e, 0x70, 0x65, 0x72, 0x69, 0x73, 0x63, 0x6f, 0x2e, 0x49,
	0x50, 0x52, 0x02, 0x69, 0x70, 0x12, 0x1f, 0x0a, 0x02, 0x6c, 0x34, 0x18, 0x04, 0x20, 0x01, 0x28,
	0x0b, 0x32, 0x0f, 0x2e, 0x70, 0x65, 0x72, 0x69, 0x73, 0x63, 0x6f, 0x2e, 0x4c, 0x61, 0x79, 0x65,
	0x72, 0x34, 0x52, 0x02, 0x6c, 0x34, 0x12, 0x1f, 0x0a, 0x02, 0x6c, 0x37, 0x18, 0x05, 0x20, 0x01,
	0x28, 0x0b, 0x32, 0x0f, 0x2e, 0x70, 0x65, 0x72, 0x69, 0x73, 0x63, 0x6f, 0x2e, 0x4c, 0x61, 0x79,
	0x65, 0x72, 0x37, 0x52, 0x02, 0x6c, 0x37, 0x22, 0x66, 0x0a, 0x02, 0x49, 0x50, 0x12, 0x16, 0x0a,
	0x06, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x06, 0x63,
	0x6c, 0x69, 0x65, 0x6e, 0x74, 0x12, 0x16, 0x0a, 0x06, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x18,
	0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x06, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x12, 0x30, 0x0a,
	0x09, 0x69, 0x70, 0x56, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0e,
	0x32, 0x12, 0x2e, 0x70, 0x65, 0x72, 0x69, 0x73, 0x63, 0x6f, 0x2e, 0x49, 0x50, 0x56, 0x65, 0x72,
	0x73, 0x69, 0x6f, 0x6e, 0x52, 0x09, 0x69, 0x70, 0x56, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x22,
	0x58, 0x0a, 0x06, 0x4c, 0x61, 0x79, 0x65, 0x72, 0x34, 0x12, 0x20, 0x0a, 0x03, 0x54, 0x43, 0x50,
	0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x0c, 0x2e, 0x70, 0x65, 0x72, 0x69, 0x73, 0x63, 0x6f,
	0x2e, 0x54, 0x43, 0x50, 0x48, 0x00, 0x52, 0x03, 0x54, 0x43, 0x50, 0x12, 0x20, 0x0a, 0x03, 0x55,
	0x44, 0x50, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x0c, 0x2e, 0x70, 0x65, 0x72, 0x69, 0x73,
	0x63, 0x6f, 0x2e, 0x55, 0x44, 0x50, 0x48, 0x00, 0x52, 0x03, 0x55, 0x44, 0x50, 0x42, 0x0a, 0x0a,
	0x08, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x63, 0x6f, 0x6c, 0x22, 0x47, 0x0a, 0x03, 0x54, 0x43, 0x50,
	0x12, 0x1f, 0x0a, 0x0b, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x5f, 0x70, 0x6f, 0x72, 0x74, 0x18,
	0x01, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x0a, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x50, 0x6f, 0x72,
	0x74, 0x12, 0x1f, 0x0a, 0x0b, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x5f, 0x70, 0x6f, 0x72, 0x74,
	0x18, 0x02, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x0a, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x50, 0x6f,
	0x72, 0x74, 0x22, 0x47, 0x0a, 0x03, 0x55, 0x44, 0x50, 0x12, 0x1f, 0x0a, 0x0b, 0x63, 0x6c, 0x69,
	0x65, 0x6e, 0x74, 0x5f, 0x70, 0x6f, 0x72, 0x74, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x0a,
	0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x50, 0x6f, 0x72, 0x74, 0x12, 0x1f, 0x0a, 0x0b, 0x73, 0x65,
	0x72, 0x76, 0x65, 0x72, 0x5f, 0x70, 0x6f, 0x72, 0x74, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0d, 0x52,
	0x0a, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x50, 0x6f, 0x72, 0x74, 0x22, 0x82, 0x01, 0x0a, 0x06,
	0x4c, 0x61, 0x79, 0x65, 0x72, 0x37, 0x12, 0x1d, 0x0a, 0x0a, 0x6c, 0x61, 0x74, 0x65, 0x6e, 0x63,
	0x79, 0x5f, 0x6e, 0x73, 0x18, 0x01, 0x20, 0x01, 0x28, 0x04, 0x52, 0x09, 0x6c, 0x61, 0x74, 0x65,
	0x6e, 0x63, 0x79, 0x4e, 0x73, 0x12, 0x2a, 0x0a, 0x07, 0x72, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74,
	0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x10, 0x2e, 0x70, 0x65, 0x72, 0x69, 0x73, 0x63, 0x6f,
	0x2e, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x52, 0x07, 0x72, 0x65, 0x71, 0x75, 0x65, 0x73,
	0x74, 0x12, 0x2d, 0x0a, 0x08, 0x72, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x18, 0x03, 0x20,
	0x01, 0x28, 0x0b, 0x32, 0x11, 0x2e, 0x70, 0x65, 0x72, 0x69, 0x73, 0x63, 0x6f, 0x2e, 0x52, 0x65,
	0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x52, 0x08, 0x72, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65,
	0x22, 0x3f, 0x0a, 0x07, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x2a, 0x0a, 0x04, 0x68,
	0x74, 0x74, 0x70, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x14, 0x2e, 0x70, 0x65, 0x72, 0x69,
	0x73, 0x63, 0x6f, 0x2e, 0x48, 0x54, 0x54, 0x50, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x48,
	0x00, 0x52, 0x04, 0x68, 0x74, 0x74, 0x70, 0x42, 0x08, 0x0a, 0x06, 0x72, 0x65, 0x63, 0x6f, 0x72,
	0x64, 0x22, 0x41, 0x0a, 0x08, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x2b, 0x0a,
	0x04, 0x68, 0x74, 0x74, 0x70, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x15, 0x2e, 0x70, 0x65,
	0x72, 0x69, 0x73, 0x63, 0x6f, 0x2e, 0x48, 0x54, 0x54, 0x50, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e,
	0x73, 0x65, 0x48, 0x00, 0x52, 0x04, 0x68, 0x74, 0x74, 0x70, 0x42, 0x08, 0x0a, 0x06, 0x72, 0x65,
	0x63, 0x6f, 0x72, 0x64, 0x22, 0x82, 0x01, 0x0a, 0x0b, 0x48, 0x54, 0x54, 0x50, 0x52, 0x65, 0x71,
	0x75, 0x65, 0x73, 0x74, 0x12, 0x1a, 0x0a, 0x08, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x63, 0x6f, 0x6c,
	0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x08, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x63, 0x6f, 0x6c,
	0x12, 0x16, 0x0a, 0x06, 0x6d, 0x65, 0x74, 0x68, 0x6f, 0x64, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09,
	0x52, 0x06, 0x6d, 0x65, 0x74, 0x68, 0x6f, 0x64, 0x12, 0x10, 0x0a, 0x03, 0x75, 0x72, 0x6c, 0x18,
	0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x03, 0x75, 0x72, 0x6c, 0x12, 0x2d, 0x0a, 0x07, 0x68, 0x65,
	0x61, 0x64, 0x65, 0x72, 0x73, 0x18, 0x04, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x13, 0x2e, 0x70, 0x65,
	0x72, 0x69, 0x73, 0x63, 0x6f, 0x2e, 0x48, 0x54, 0x54, 0x50, 0x48, 0x65, 0x61, 0x64, 0x65, 0x72,
	0x52, 0x07, 0x68, 0x65, 0x61, 0x64, 0x65, 0x72, 0x73, 0x22, 0x6d, 0x0a, 0x0c, 0x48, 0x54, 0x54,
	0x50, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x1a, 0x0a, 0x08, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x63, 0x6f, 0x6c, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x08, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x63, 0x6f, 0x6c, 0x12, 0x12, 0x0a, 0x04, 0x63, 0x6f, 0x64, 0x65, 0x18, 0x05, 0x20,
	0x01, 0x28, 0x0d, 0x52, 0x04, 0x63, 0x6f, 0x64, 0x65, 0x12, 0x2d, 0x0a, 0x07, 0x68, 0x65, 0x61,
	0x64, 0x65, 0x72, 0x73, 0x18, 0x07, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x13, 0x2e, 0x70, 0x65, 0x72,
	0x69, 0x73, 0x63, 0x6f, 0x2e, 0x48, 0x54, 0x54, 0x50, 0x48, 0x65, 0x61, 0x64, 0x65, 0x72, 0x52,
	0x07, 0x68, 0x65, 0x61, 0x64, 0x65, 0x72, 0x73, 0x22, 0x34, 0x0a, 0x0a, 0x48, 0x54, 0x54, 0x50,
	0x48, 0x65, 0x61, 0x64, 0x65, 0x72, 0x12, 0x10, 0x0a, 0x03, 0x6b, 0x65, 0x79, 0x18, 0x01, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x03, 0x6b, 0x65, 0x79, 0x12, 0x14, 0x0a, 0x05, 0x76, 0x61, 0x6c, 0x75,
	0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x2a, 0x2f,
	0x0a, 0x09, 0x49, 0x50, 0x56, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x12, 0x0e, 0x0a, 0x0a, 0x49,
	0x50, 0x5f, 0x55, 0x4e, 0x4b, 0x4e, 0x4f, 0x57, 0x4e, 0x10, 0x00, 0x12, 0x08, 0x0a, 0x04, 0x49,
	0x50, 0x76, 0x34, 0x10, 0x01, 0x12, 0x08, 0x0a, 0x04, 0x49, 0x50, 0x76, 0x36, 0x10, 0x02, 0x42,
	0x2e, 0x5a, 0x2c, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x4b, 0x75,
	0x6d, 0x4b, 0x65, 0x65, 0x48, 0x79, 0x75, 0x6e, 0x2f, 0x70, 0x65, 0x72, 0x69, 0x73, 0x63, 0x6f,
	0x2f, 0x61, 0x70, 0x69, 0x2f, 0x76, 0x31, 0x2f, 0x70, 0x65, 0x72, 0x69, 0x73, 0x63, 0x6f, 0x62,
	0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_perisco_proto_rawDescOnce sync.Once
	file_perisco_proto_rawDescData = file_perisco_proto_rawDesc
)

func file_perisco_proto_rawDescGZIP() []byte {
	file_perisco_proto_rawDescOnce.Do(func() {
		file_perisco_proto_rawDescData = protoimpl.X.CompressGZIP(file_perisco_proto_rawDescData)
	})
	return file_perisco_proto_rawDescData
}

var file_perisco_proto_enumTypes = make([]protoimpl.EnumInfo, 1)
var file_perisco_proto_msgTypes = make([]protoimpl.MessageInfo, 11)
var file_perisco_proto_goTypes = []interface{}{
	(IPVersion)(0),                // 0: perisco.IPVersion
	(*ProtoMessage)(nil),          // 1: perisco.ProtoMessage
	(*IP)(nil),                    // 2: perisco.IP
	(*Layer4)(nil),                // 3: perisco.Layer4
	(*TCP)(nil),                   // 4: perisco.TCP
	(*UDP)(nil),                   // 5: perisco.UDP
	(*Layer7)(nil),                // 6: perisco.Layer7
	(*Request)(nil),               // 7: perisco.Request
	(*Response)(nil),              // 8: perisco.Response
	(*HTTPRequest)(nil),           // 9: perisco.HTTPRequest
	(*HTTPResponse)(nil),          // 10: perisco.HTTPResponse
	(*HTTPHeader)(nil),            // 11: perisco.HTTPHeader
	(*timestamppb.Timestamp)(nil), // 12: google.protobuf.Timestamp
}
var file_perisco_proto_depIdxs = []int32{
	12, // 0: perisco.ProtoMessage.ts:type_name -> google.protobuf.Timestamp
	2,  // 1: perisco.ProtoMessage.ip:type_name -> perisco.IP
	3,  // 2: perisco.ProtoMessage.l4:type_name -> perisco.Layer4
	6,  // 3: perisco.ProtoMessage.l7:type_name -> perisco.Layer7
	0,  // 4: perisco.IP.ipVersion:type_name -> perisco.IPVersion
	4,  // 5: perisco.Layer4.TCP:type_name -> perisco.TCP
	5,  // 6: perisco.Layer4.UDP:type_name -> perisco.UDP
	7,  // 7: perisco.Layer7.request:type_name -> perisco.Request
	8,  // 8: perisco.Layer7.response:type_name -> perisco.Response
	9,  // 9: perisco.Request.http:type_name -> perisco.HTTPRequest
	10, // 10: perisco.Response.http:type_name -> perisco.HTTPResponse
	11, // 11: perisco.HTTPRequest.headers:type_name -> perisco.HTTPHeader
	11, // 12: perisco.HTTPResponse.headers:type_name -> perisco.HTTPHeader
	13, // [13:13] is the sub-list for method output_type
	13, // [13:13] is the sub-list for method input_type
	13, // [13:13] is the sub-list for extension type_name
	13, // [13:13] is the sub-list for extension extendee
	0,  // [0:13] is the sub-list for field type_name
}

func init() { file_perisco_proto_init() }
func file_perisco_proto_init() {
	if File_perisco_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_perisco_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ProtoMessage); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_perisco_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*IP); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_perisco_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Layer4); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_perisco_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*TCP); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_perisco_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*UDP); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_perisco_proto_msgTypes[5].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Layer7); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_perisco_proto_msgTypes[6].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Request); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_perisco_proto_msgTypes[7].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Response); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_perisco_proto_msgTypes[8].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*HTTPRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_perisco_proto_msgTypes[9].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*HTTPResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_perisco_proto_msgTypes[10].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*HTTPHeader); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	file_perisco_proto_msgTypes[2].OneofWrappers = []interface{}{
		(*Layer4_TCP)(nil),
		(*Layer4_UDP)(nil),
	}
	file_perisco_proto_msgTypes[6].OneofWrappers = []interface{}{
		(*Request_Http)(nil),
	}
	file_perisco_proto_msgTypes[7].OneofWrappers = []interface{}{
		(*Response_Http)(nil),
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_perisco_proto_rawDesc,
			NumEnums:      1,
			NumMessages:   11,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_perisco_proto_goTypes,
		DependencyIndexes: file_perisco_proto_depIdxs,
		EnumInfos:         file_perisco_proto_enumTypes,
		MessageInfos:      file_perisco_proto_msgTypes,
	}.Build()
	File_perisco_proto = out.File
	file_perisco_proto_rawDesc = nil
	file_perisco_proto_goTypes = nil
	file_perisco_proto_depIdxs = nil
}
