// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.28.1
// 	protoc        v3.21.6
// source: packet.proto

package pb

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

type Packet struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Pcap      *Packet_Pcap           `protobuf:"bytes,1,opt,name=pcap,proto3" json:"pcap,omitempty"`
	Meta      *Packet_Metadata       `protobuf:"bytes,2,opt,name=meta,proto3" json:"meta,omitempty"`
	Timestamp *timestamppb.Timestamp `protobuf:"bytes,3,opt,name=timestamp,proto3" json:"timestamp,omitempty"`
	Iface     *Packet_Interface      `protobuf:"bytes,4,opt,name=iface,proto3" json:"iface,omitempty"`
	L2        *Packet_Layer2         `protobuf:"bytes,5,opt,name=l2,proto3" json:"l2,omitempty"`
	// Types that are assignable to L3:
	//
	//	*Packet_Ip
	//	*Packet_Ip4
	//	*Packet_Ip6
	L3 isPacket_L3 `protobuf_oneof:"l3"`
}

func (x *Packet) Reset() {
	*x = Packet{}
	if protoimpl.UnsafeEnabled {
		mi := &file_packet_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Packet) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Packet) ProtoMessage() {}

func (x *Packet) ProtoReflect() protoreflect.Message {
	mi := &file_packet_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Packet.ProtoReflect.Descriptor instead.
func (*Packet) Descriptor() ([]byte, []int) {
	return file_packet_proto_rawDescGZIP(), []int{0}
}

func (x *Packet) GetPcap() *Packet_Pcap {
	if x != nil {
		return x.Pcap
	}
	return nil
}

func (x *Packet) GetMeta() *Packet_Metadata {
	if x != nil {
		return x.Meta
	}
	return nil
}

func (x *Packet) GetTimestamp() *timestamppb.Timestamp {
	if x != nil {
		return x.Timestamp
	}
	return nil
}

func (x *Packet) GetIface() *Packet_Interface {
	if x != nil {
		return x.Iface
	}
	return nil
}

func (x *Packet) GetL2() *Packet_Layer2 {
	if x != nil {
		return x.L2
	}
	return nil
}

func (m *Packet) GetL3() isPacket_L3 {
	if m != nil {
		return m.L3
	}
	return nil
}

func (x *Packet) GetIp() *Packet_Layer3 {
	if x, ok := x.GetL3().(*Packet_Ip); ok {
		return x.Ip
	}
	return nil
}

func (x *Packet) GetIp4() *Packet_IPv4 {
	if x, ok := x.GetL3().(*Packet_Ip4); ok {
		return x.Ip4
	}
	return nil
}

func (x *Packet) GetIp6() *Packet_IPv6 {
	if x, ok := x.GetL3().(*Packet_Ip6); ok {
		return x.Ip6
	}
	return nil
}

type isPacket_L3 interface {
	isPacket_L3()
}

type Packet_Ip struct {
	Ip *Packet_Layer3 `protobuf:"bytes,6,opt,name=ip,proto3,oneof"`
}

type Packet_Ip4 struct {
	Ip4 *Packet_IPv4 `protobuf:"bytes,7,opt,name=ip4,proto3,oneof"`
}

type Packet_Ip6 struct {
	Ip6 *Packet_IPv6 `protobuf:"bytes,8,opt,name=ip6,proto3,oneof"`
}

func (*Packet_Ip) isPacket_L3() {}

func (*Packet_Ip4) isPacket_L3() {}

func (*Packet_Ip6) isPacket_L3() {}

type Packet_Pcap struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Context string `protobuf:"bytes,1,opt,name=context,proto3" json:"context,omitempty"`
	Serial  uint64 `protobuf:"varint,2,opt,name=serial,proto3" json:"serial,omitempty"`
}

func (x *Packet_Pcap) Reset() {
	*x = Packet_Pcap{}
	if protoimpl.UnsafeEnabled {
		mi := &file_packet_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Packet_Pcap) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Packet_Pcap) ProtoMessage() {}

func (x *Packet_Pcap) ProtoReflect() protoreflect.Message {
	mi := &file_packet_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Packet_Pcap.ProtoReflect.Descriptor instead.
func (*Packet_Pcap) Descriptor() ([]byte, []int) {
	return file_packet_proto_rawDescGZIP(), []int{0, 0}
}

func (x *Packet_Pcap) GetContext() string {
	if x != nil {
		return x.Context
	}
	return ""
}

func (x *Packet_Pcap) GetSerial() uint64 {
	if x != nil {
		return x.Serial
	}
	return 0
}

type Packet_Metadata struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Truncated     bool   `protobuf:"varint,1,opt,name=truncated,proto3" json:"truncated,omitempty"`
	Length        uint64 `protobuf:"varint,2,opt,name=length,proto3" json:"length,omitempty"`
	CaptureLength uint64 `protobuf:"varint,3,opt,name=capture_length,json=captureLength,proto3" json:"capture_length,omitempty"`
}

func (x *Packet_Metadata) Reset() {
	*x = Packet_Metadata{}
	if protoimpl.UnsafeEnabled {
		mi := &file_packet_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Packet_Metadata) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Packet_Metadata) ProtoMessage() {}

func (x *Packet_Metadata) ProtoReflect() protoreflect.Message {
	mi := &file_packet_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Packet_Metadata.ProtoReflect.Descriptor instead.
func (*Packet_Metadata) Descriptor() ([]byte, []int) {
	return file_packet_proto_rawDescGZIP(), []int{0, 1}
}

func (x *Packet_Metadata) GetTruncated() bool {
	if x != nil {
		return x.Truncated
	}
	return false
}

func (x *Packet_Metadata) GetLength() uint64 {
	if x != nil {
		return x.Length
	}
	return 0
}

func (x *Packet_Metadata) GetCaptureLength() uint64 {
	if x != nil {
		return x.CaptureLength
	}
	return 0
}

type Packet_Interface struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Index uint32   `protobuf:"varint,1,opt,name=index,proto3" json:"index,omitempty"`
	Name  string   `protobuf:"bytes,2,opt,name=name,proto3" json:"name,omitempty"`
	Addrs []string `protobuf:"bytes,3,rep,name=addrs,proto3" json:"addrs,omitempty"`
}

func (x *Packet_Interface) Reset() {
	*x = Packet_Interface{}
	if protoimpl.UnsafeEnabled {
		mi := &file_packet_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Packet_Interface) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Packet_Interface) ProtoMessage() {}

func (x *Packet_Interface) ProtoReflect() protoreflect.Message {
	mi := &file_packet_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Packet_Interface.ProtoReflect.Descriptor instead.
func (*Packet_Interface) Descriptor() ([]byte, []int) {
	return file_packet_proto_rawDescGZIP(), []int{0, 2}
}

func (x *Packet_Interface) GetIndex() uint32 {
	if x != nil {
		return x.Index
	}
	return 0
}

func (x *Packet_Interface) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (x *Packet_Interface) GetAddrs() []string {
	if x != nil {
		return x.Addrs
	}
	return nil
}

type Packet_Layer2 struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Source string `protobuf:"bytes,1,opt,name=source,proto3" json:"source,omitempty"`
	Target string `protobuf:"bytes,2,opt,name=target,proto3" json:"target,omitempty"`
	Type   string `protobuf:"bytes,3,opt,name=type,proto3" json:"type,omitempty"`
}

func (x *Packet_Layer2) Reset() {
	*x = Packet_Layer2{}
	if protoimpl.UnsafeEnabled {
		mi := &file_packet_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Packet_Layer2) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Packet_Layer2) ProtoMessage() {}

func (x *Packet_Layer2) ProtoReflect() protoreflect.Message {
	mi := &file_packet_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Packet_Layer2.ProtoReflect.Descriptor instead.
func (*Packet_Layer2) Descriptor() ([]byte, []int) {
	return file_packet_proto_rawDescGZIP(), []int{0, 3}
}

func (x *Packet_Layer2) GetSource() string {
	if x != nil {
		return x.Source
	}
	return ""
}

func (x *Packet_Layer2) GetTarget() string {
	if x != nil {
		return x.Target
	}
	return ""
}

func (x *Packet_Layer2) GetType() string {
	if x != nil {
		return x.Type
	}
	return ""
}

type Packet_Layer3 struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Source string `protobuf:"bytes,1,opt,name=source,proto3" json:"source,omitempty"`
	Target string `protobuf:"bytes,2,opt,name=target,proto3" json:"target,omitempty"`
}

func (x *Packet_Layer3) Reset() {
	*x = Packet_Layer3{}
	if protoimpl.UnsafeEnabled {
		mi := &file_packet_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Packet_Layer3) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Packet_Layer3) ProtoMessage() {}

func (x *Packet_Layer3) ProtoReflect() protoreflect.Message {
	mi := &file_packet_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Packet_Layer3.ProtoReflect.Descriptor instead.
func (*Packet_Layer3) Descriptor() ([]byte, []int) {
	return file_packet_proto_rawDescGZIP(), []int{0, 4}
}

func (x *Packet_Layer3) GetSource() string {
	if x != nil {
		return x.Source
	}
	return ""
}

func (x *Packet_Layer3) GetTarget() string {
	if x != nil {
		return x.Target
	}
	return ""
}

type Packet_IPv4 struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Source uint32 `protobuf:"fixed32,1,opt,name=source,proto3" json:"source,omitempty"`
	Target uint32 `protobuf:"fixed32,2,opt,name=target,proto3" json:"target,omitempty"`
}

func (x *Packet_IPv4) Reset() {
	*x = Packet_IPv4{}
	if protoimpl.UnsafeEnabled {
		mi := &file_packet_proto_msgTypes[6]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Packet_IPv4) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Packet_IPv4) ProtoMessage() {}

func (x *Packet_IPv4) ProtoReflect() protoreflect.Message {
	mi := &file_packet_proto_msgTypes[6]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Packet_IPv4.ProtoReflect.Descriptor instead.
func (*Packet_IPv4) Descriptor() ([]byte, []int) {
	return file_packet_proto_rawDescGZIP(), []int{0, 5}
}

func (x *Packet_IPv4) GetSource() uint32 {
	if x != nil {
		return x.Source
	}
	return 0
}

func (x *Packet_IPv4) GetTarget() uint32 {
	if x != nil {
		return x.Target
	}
	return 0
}

type Packet_IPv6 struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Source []byte `protobuf:"bytes,1,opt,name=source,proto3" json:"source,omitempty"`
	Target []byte `protobuf:"bytes,2,opt,name=target,proto3" json:"target,omitempty"`
}

func (x *Packet_IPv6) Reset() {
	*x = Packet_IPv6{}
	if protoimpl.UnsafeEnabled {
		mi := &file_packet_proto_msgTypes[7]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Packet_IPv6) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Packet_IPv6) ProtoMessage() {}

func (x *Packet_IPv6) ProtoReflect() protoreflect.Message {
	mi := &file_packet_proto_msgTypes[7]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Packet_IPv6.ProtoReflect.Descriptor instead.
func (*Packet_IPv6) Descriptor() ([]byte, []int) {
	return file_packet_proto_rawDescGZIP(), []int{0, 6}
}

func (x *Packet_IPv6) GetSource() []byte {
	if x != nil {
		return x.Source
	}
	return nil
}

func (x *Packet_IPv6) GetTarget() []byte {
	if x != nil {
		return x.Target
	}
	return nil
}

var File_packet_proto protoreflect.FileDescriptor

var file_packet_proto_rawDesc = []byte{
	0x0a, 0x0c, 0x70, 0x61, 0x63, 0x6b, 0x65, 0x74, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x1f,
	0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f,
	0x74, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22,
	0xa7, 0x06, 0x0a, 0x06, 0x50, 0x61, 0x63, 0x6b, 0x65, 0x74, 0x12, 0x20, 0x0a, 0x04, 0x70, 0x63,
	0x61, 0x70, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x0c, 0x2e, 0x50, 0x61, 0x63, 0x6b, 0x65,
	0x74, 0x2e, 0x50, 0x63, 0x61, 0x70, 0x52, 0x04, 0x70, 0x63, 0x61, 0x70, 0x12, 0x24, 0x0a, 0x04,
	0x6d, 0x65, 0x74, 0x61, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x10, 0x2e, 0x50, 0x61, 0x63,
	0x6b, 0x65, 0x74, 0x2e, 0x4d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61, 0x52, 0x04, 0x6d, 0x65,
	0x74, 0x61, 0x12, 0x38, 0x0a, 0x09, 0x74, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x18,
	0x03, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1a, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d,
	0x70, 0x52, 0x09, 0x74, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x12, 0x27, 0x0a, 0x05,
	0x69, 0x66, 0x61, 0x63, 0x65, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x11, 0x2e, 0x50, 0x61,
	0x63, 0x6b, 0x65, 0x74, 0x2e, 0x49, 0x6e, 0x74, 0x65, 0x72, 0x66, 0x61, 0x63, 0x65, 0x52, 0x05,
	0x69, 0x66, 0x61, 0x63, 0x65, 0x12, 0x1e, 0x0a, 0x02, 0x6c, 0x32, 0x18, 0x05, 0x20, 0x01, 0x28,
	0x0b, 0x32, 0x0e, 0x2e, 0x50, 0x61, 0x63, 0x6b, 0x65, 0x74, 0x2e, 0x4c, 0x61, 0x79, 0x65, 0x72,
	0x32, 0x52, 0x02, 0x6c, 0x32, 0x12, 0x20, 0x0a, 0x02, 0x69, 0x70, 0x18, 0x06, 0x20, 0x01, 0x28,
	0x0b, 0x32, 0x0e, 0x2e, 0x50, 0x61, 0x63, 0x6b, 0x65, 0x74, 0x2e, 0x4c, 0x61, 0x79, 0x65, 0x72,
	0x33, 0x48, 0x00, 0x52, 0x02, 0x69, 0x70, 0x12, 0x20, 0x0a, 0x03, 0x69, 0x70, 0x34, 0x18, 0x07,
	0x20, 0x01, 0x28, 0x0b, 0x32, 0x0c, 0x2e, 0x50, 0x61, 0x63, 0x6b, 0x65, 0x74, 0x2e, 0x49, 0x50,
	0x76, 0x34, 0x48, 0x00, 0x52, 0x03, 0x69, 0x70, 0x34, 0x12, 0x20, 0x0a, 0x03, 0x69, 0x70, 0x36,
	0x18, 0x08, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x0c, 0x2e, 0x50, 0x61, 0x63, 0x6b, 0x65, 0x74, 0x2e,
	0x49, 0x50, 0x76, 0x36, 0x48, 0x00, 0x52, 0x03, 0x69, 0x70, 0x36, 0x1a, 0x38, 0x0a, 0x04, 0x50,
	0x63, 0x61, 0x70, 0x12, 0x18, 0x0a, 0x07, 0x63, 0x6f, 0x6e, 0x74, 0x65, 0x78, 0x74, 0x18, 0x01,
	0x20, 0x01, 0x28, 0x09, 0x52, 0x07, 0x63, 0x6f, 0x6e, 0x74, 0x65, 0x78, 0x74, 0x12, 0x16, 0x0a,
	0x06, 0x73, 0x65, 0x72, 0x69, 0x61, 0x6c, 0x18, 0x02, 0x20, 0x01, 0x28, 0x04, 0x52, 0x06, 0x73,
	0x65, 0x72, 0x69, 0x61, 0x6c, 0x1a, 0x67, 0x0a, 0x08, 0x4d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74,
	0x61, 0x12, 0x1c, 0x0a, 0x09, 0x74, 0x72, 0x75, 0x6e, 0x63, 0x61, 0x74, 0x65, 0x64, 0x18, 0x01,
	0x20, 0x01, 0x28, 0x08, 0x52, 0x09, 0x74, 0x72, 0x75, 0x6e, 0x63, 0x61, 0x74, 0x65, 0x64, 0x12,
	0x16, 0x0a, 0x06, 0x6c, 0x65, 0x6e, 0x67, 0x74, 0x68, 0x18, 0x02, 0x20, 0x01, 0x28, 0x04, 0x52,
	0x06, 0x6c, 0x65, 0x6e, 0x67, 0x74, 0x68, 0x12, 0x25, 0x0a, 0x0e, 0x63, 0x61, 0x70, 0x74, 0x75,
	0x72, 0x65, 0x5f, 0x6c, 0x65, 0x6e, 0x67, 0x74, 0x68, 0x18, 0x03, 0x20, 0x01, 0x28, 0x04, 0x52,
	0x0d, 0x63, 0x61, 0x70, 0x74, 0x75, 0x72, 0x65, 0x4c, 0x65, 0x6e, 0x67, 0x74, 0x68, 0x1a, 0x4b,
	0x0a, 0x09, 0x49, 0x6e, 0x74, 0x65, 0x72, 0x66, 0x61, 0x63, 0x65, 0x12, 0x14, 0x0a, 0x05, 0x69,
	0x6e, 0x64, 0x65, 0x78, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x05, 0x69, 0x6e, 0x64, 0x65,
	0x78, 0x12, 0x12, 0x0a, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x04, 0x6e, 0x61, 0x6d, 0x65, 0x12, 0x14, 0x0a, 0x05, 0x61, 0x64, 0x64, 0x72, 0x73, 0x18, 0x03,
	0x20, 0x03, 0x28, 0x09, 0x52, 0x05, 0x61, 0x64, 0x64, 0x72, 0x73, 0x1a, 0x4c, 0x0a, 0x06, 0x4c,
	0x61, 0x79, 0x65, 0x72, 0x32, 0x12, 0x16, 0x0a, 0x06, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x18,
	0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x06, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x12, 0x16, 0x0a,
	0x06, 0x74, 0x61, 0x72, 0x67, 0x65, 0x74, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x06, 0x74,
	0x61, 0x72, 0x67, 0x65, 0x74, 0x12, 0x12, 0x0a, 0x04, 0x74, 0x79, 0x70, 0x65, 0x18, 0x03, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x04, 0x74, 0x79, 0x70, 0x65, 0x1a, 0x38, 0x0a, 0x06, 0x4c, 0x61, 0x79,
	0x65, 0x72, 0x33, 0x12, 0x16, 0x0a, 0x06, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x18, 0x01, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x06, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x12, 0x16, 0x0a, 0x06, 0x74,
	0x61, 0x72, 0x67, 0x65, 0x74, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x06, 0x74, 0x61, 0x72,
	0x67, 0x65, 0x74, 0x1a, 0x36, 0x0a, 0x04, 0x49, 0x50, 0x76, 0x34, 0x12, 0x16, 0x0a, 0x06, 0x73,
	0x6f, 0x75, 0x72, 0x63, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x07, 0x52, 0x06, 0x73, 0x6f, 0x75,
	0x72, 0x63, 0x65, 0x12, 0x16, 0x0a, 0x06, 0x74, 0x61, 0x72, 0x67, 0x65, 0x74, 0x18, 0x02, 0x20,
	0x01, 0x28, 0x07, 0x52, 0x06, 0x74, 0x61, 0x72, 0x67, 0x65, 0x74, 0x1a, 0x36, 0x0a, 0x04, 0x49,
	0x50, 0x76, 0x36, 0x12, 0x16, 0x0a, 0x06, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x18, 0x01, 0x20,
	0x01, 0x28, 0x0c, 0x52, 0x06, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x12, 0x16, 0x0a, 0x06, 0x74,
	0x61, 0x72, 0x67, 0x65, 0x74, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x06, 0x74, 0x61, 0x72,
	0x67, 0x65, 0x74, 0x42, 0x04, 0x0a, 0x02, 0x6c, 0x33, 0x42, 0x27, 0x5a, 0x25, 0x67, 0x69, 0x74,
	0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x67, 0x63, 0x68, 0x75, 0x78, 0x2f, 0x70, 0x63,
	0x61, 0x70, 0x2d, 0x63, 0x6c, 0x69, 0x2f, 0x69, 0x6e, 0x74, 0x65, 0x72, 0x6e, 0x61, 0x6c, 0x2f,
	0x70, 0x62, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_packet_proto_rawDescOnce sync.Once
	file_packet_proto_rawDescData = file_packet_proto_rawDesc
)

func file_packet_proto_rawDescGZIP() []byte {
	file_packet_proto_rawDescOnce.Do(func() {
		file_packet_proto_rawDescData = protoimpl.X.CompressGZIP(file_packet_proto_rawDescData)
	})
	return file_packet_proto_rawDescData
}

var file_packet_proto_msgTypes = make([]protoimpl.MessageInfo, 8)
var file_packet_proto_goTypes = []interface{}{
	(*Packet)(nil),                // 0: Packet
	(*Packet_Pcap)(nil),           // 1: Packet.Pcap
	(*Packet_Metadata)(nil),       // 2: Packet.Metadata
	(*Packet_Interface)(nil),      // 3: Packet.Interface
	(*Packet_Layer2)(nil),         // 4: Packet.Layer2
	(*Packet_Layer3)(nil),         // 5: Packet.Layer3
	(*Packet_IPv4)(nil),           // 6: Packet.IPv4
	(*Packet_IPv6)(nil),           // 7: Packet.IPv6
	(*timestamppb.Timestamp)(nil), // 8: google.protobuf.Timestamp
}
var file_packet_proto_depIdxs = []int32{
	1, // 0: Packet.pcap:type_name -> Packet.Pcap
	2, // 1: Packet.meta:type_name -> Packet.Metadata
	8, // 2: Packet.timestamp:type_name -> google.protobuf.Timestamp
	3, // 3: Packet.iface:type_name -> Packet.Interface
	4, // 4: Packet.l2:type_name -> Packet.Layer2
	5, // 5: Packet.ip:type_name -> Packet.Layer3
	6, // 6: Packet.ip4:type_name -> Packet.IPv4
	7, // 7: Packet.ip6:type_name -> Packet.IPv6
	8, // [8:8] is the sub-list for method output_type
	8, // [8:8] is the sub-list for method input_type
	8, // [8:8] is the sub-list for extension type_name
	8, // [8:8] is the sub-list for extension extendee
	0, // [0:8] is the sub-list for field type_name
}

func init() { file_packet_proto_init() }
func file_packet_proto_init() {
	if File_packet_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_packet_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Packet); i {
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
		file_packet_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Packet_Pcap); i {
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
		file_packet_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Packet_Metadata); i {
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
		file_packet_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Packet_Interface); i {
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
		file_packet_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Packet_Layer2); i {
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
		file_packet_proto_msgTypes[5].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Packet_Layer3); i {
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
		file_packet_proto_msgTypes[6].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Packet_IPv4); i {
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
		file_packet_proto_msgTypes[7].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Packet_IPv6); i {
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
	file_packet_proto_msgTypes[0].OneofWrappers = []interface{}{
		(*Packet_Ip)(nil),
		(*Packet_Ip4)(nil),
		(*Packet_Ip6)(nil),
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_packet_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   8,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_packet_proto_goTypes,
		DependencyIndexes: file_packet_proto_depIdxs,
		MessageInfos:      file_packet_proto_msgTypes,
	}.Build()
	File_packet_proto = out.File
	file_packet_proto_rawDesc = nil
	file_packet_proto_goTypes = nil
	file_packet_proto_depIdxs = nil
}
