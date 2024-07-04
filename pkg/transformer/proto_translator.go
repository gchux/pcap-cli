package transformer

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/gchux/pcap-cli/internal/pb"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type (
	ProtoPcapTranslator struct {
		iface *PcapIface
	}
)

func (t *ProtoPcapTranslator) next(ctx context.Context, packet *gopacket.Packet, serial *uint64) fmt.Stringer {
	// `next` returns the container to be used for merging all layers
	p := &pb.Packet{}

	metadata := (*packet).Metadata()
	info := metadata.CaptureInfo

	p.Timestamp = timestamppb.New(info.Timestamp)

	pcap := p.GetPcap()
	pcap.Context = ctx.Value(ContextID).(string)
	pcap.Serial = *serial

	meta := p.GetMeta()
	meta.Truncated = metadata.Truncated
	meta.Length = uint64(info.Length)
	meta.CaptureLength = uint64(info.CaptureLength)

	iface := p.GetIface()
	iface.Index = uint32(t.iface.Index)
	iface.Name = t.iface.Name
	addrs := make([]string, len(t.iface.Addrs))
	for i, addr := range t.iface.Addrs {
		addrs[i] = addr.IP.String()
	}
	iface.Addrs = addrs

	return p
}

func (t *ProtoPcapTranslator) asTranslation(buffer fmt.Stringer) *pb.Packet {
	// [TODO]: implement Ethernet layer translation
	return buffer.(*pb.Packet)
}

func (t *ProtoPcapTranslator) translateEthernetLayer(ctx context.Context, eth *layers.Ethernet) fmt.Stringer {
	p := &pb.Packet{}

	L2 := p.GetL2()

	L2.Source = eth.SrcMAC.String()
	L2.Target = eth.DstMAC.String()

	return p
}

func (t *ProtoPcapTranslator) translateIPv4Layer(ctx context.Context, ip *layers.IPv4) fmt.Stringer {
	// [TODO]: implement IPv4 layer translation
	p := &pb.Packet{}

	L3 := p.GetIp()

	L3.Source = ip.SrcIP.String()
	L3.Target = ip.DstIP.String()

	return p
}

func (t *ProtoPcapTranslator) translateIPv6Layer(ctx context.Context, packet *layers.IPv6) fmt.Stringer {
	// [TODO]: implement IPv6 layer translation
	p := &pb.Packet{}
	return p
}

func (t *ProtoPcapTranslator) translateUDPLayer(ctx context.Context, packet *layers.UDP) fmt.Stringer {
	// [TODO]: implement UDP layer translation
	p := &pb.Packet{}
	return p
}

func (t *ProtoPcapTranslator) translateTCPLayer(ctx context.Context, packet *layers.TCP) fmt.Stringer {
	// [TODO]: implement TCP layer translation
	p := &pb.Packet{}
	return p
}

func (t *ProtoPcapTranslator) translateTLSLayer(ctx context.Context, tls *layers.TLS) fmt.Stringer {
	// [TODO]: implement TLS layer translation
	p := &pb.Packet{}
	return p
}

func (t *ProtoPcapTranslator) translateDNSLayer(ctx context.Context, dns *layers.DNS) fmt.Stringer {
	// [TODO]: implement DNS layer translation
	p := &pb.Packet{}
	return p
}

func (t *ProtoPcapTranslator) merge(ctx context.Context, tgt fmt.Stringer, src fmt.Stringer) (fmt.Stringer, error) {
	proto.Merge(t.asTranslation(tgt), t.asTranslation(src))
	return tgt, nil
}

func (t *ProtoPcapTranslator) finalize(ctx context.Context, packet fmt.Stringer) (fmt.Stringer, error) {
	return packet, nil
}

func (t *ProtoPcapTranslator) write(ctx context.Context, writer io.Writer, packet *fmt.Stringer) (int, error) {
	protoBytes, err := proto.Marshal(t.asTranslation(*packet))
	if err != nil {
		return 0, err
	}

	protoBytesLen := len(protoBytes)

	// https://protobuf.dev/programming-guides/techniques/#streaming
	buf := make([]byte, 4)
	binary.LittleEndian.PutUint32(buf, uint32(protoBytesLen))
	if _, err := writer.Write(buf); err != nil {
		return protoBytesLen + 4, err
	}

	if _, err := writer.Write(protoBytes); err != nil {
		return protoBytesLen, err
	}

	return protoBytesLen, nil
}

func newProtoPcapTranslator(iface *PcapIface) *ProtoPcapTranslator {
	return &ProtoPcapTranslator{iface: iface}
}
