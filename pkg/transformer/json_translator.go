package transformer

import (
	"context"
	"fmt"
	"net"
	"regexp"
	"strings"
	"sync"

	"github.com/Jeffail/gabs/v2"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type JSONPcapTranslator struct {
	// [TODO]: this should be shared by all translators
	ifaces sync.Map
}

func (t *JSONPcapTranslator) translate(packet *gopacket.Packet) error {
	return fmt.Errorf("not implemented")
}

// return pointer to `struct` `gabs.Container`
func (t *JSONPcapTranslator) next(ctx context.Context, packet *gopacket.Packet, serial *int64) fmt.Stringer {
	json := gabs.New()

	json.SetP(ctx.Value("id"), "pcap.ctx")
	json.SetP(*serial, "pcap.num")

	p := *packet

	metadata := p.Metadata()
	info := metadata.CaptureInfo

	json.SetP(metadata.Truncated, "meta.trunc")
	json.SetP(info.Length, "meta.len")
	json.SetP(info.CaptureLength, "meta.cap_len")

	json.SetP(info.Timestamp, "timestamp.str")
	json.SetP(info.Timestamp.UnixMicro(), "timestamp.usec")

	ifaceIndex := info.InterfaceIndex
	var (
		iface any
		ok    bool
		err   error
	)
	if iface, ok = t.ifaces.Load(ifaceIndex); !ok {
		if iface, err = net.InterfaceByIndex(ifaceIndex); err != nil {
			return json
		}
	}

	iface, _ = t.ifaces.LoadOrStore(ifaceIndex, iface)
	netIface := iface.(*net.Interface)

	json.SetP(netIface.Index, "iface.index")
	json.SetP(netIface.Name, "iface.name")
	json.SetP(netIface.HardwareAddr.String(), "iface.hwadd")

	return json
}

func (t *JSONPcapTranslator) asTranslation(buffer fmt.Stringer) *gabs.Container {
	return buffer.(*gabs.Container)
}

func (t *JSONPcapTranslator) translateEthernetLayer(ctx context.Context, eth *layers.Ethernet) fmt.Stringer {
	json := gabs.New()

	json.SetP(eth.EthernetType.String(), "L2.type")
	json.SetP(eth.SrcMAC.String(), "L2.src")
	json.SetP(eth.DstMAC.String(), "L2.dst")

	return json
}

func (t *JSONPcapTranslator) translateIPv4Layer(ctx context.Context, ip *layers.IPv4) fmt.Stringer {
	json := gabs.New()

	// https://github.com/google/gopacket/blob/master/layers/ip4.go#L43

	json.SetP(ip.Version, "L3.v")
	json.SetP(ip.SrcIP, "L3.src")
	json.SetP(ip.DstIP, "L3.dst")
	json.SetP(ip.Id, "L3.id")
	json.SetP(ip.IHL, "L3.ihl")
	json.SetP(ip.TTL, "L3.ttl")
	json.SetP(ip.TOS, "L3.tos")
	json.SetP(ip.Length, "L3.len")
	json.SetP(ip.FragOffset, "L3.frag_offset")
	json.SetP(ip.Checksum, "L3.checksum")
	json.SetP(ip.Options, "L3.opts")

	json.SetP(ip.Protocol.String(), "L3.proto")

	// https://github.com/google/gopacket/blob/master/layers/ip4.go#L28-L40
	json.SetP(strings.Split(ip.Flags.String(), "|"), "L3.flags")

	return json
}

func (t *JSONPcapTranslator) translateIPv6Layer(ctx context.Context, ip *layers.IPv6) fmt.Stringer {
	json := gabs.New()

	// https://github.com/google/gopacket/blob/master/layers/ip6.go#L28-L43

	json.SetP(ip.Version, "L3.v")
	json.SetP(ip.SrcIP, "L3.src")
	json.SetP(ip.DstIP, "L3.dst")
	json.SetP(ip.Length, "L3.len")
	json.SetP(ip.TrafficClass, "L3.traffic_class")
	json.SetP(ip.FlowLabel, "L3.flow_label")
	json.SetP(ip.NextHeader.String(), "L3.next_header")
	json.SetP(ip.HopLimit, "L3.hop_limit")

	// missing `HopByHop`: https://github.com/google/gopacket/blob/master/layers/ip6.go#L40
	return json
}

func (t *JSONPcapTranslator) translateUDPLayer(ctx context.Context, udp *layers.UDP) fmt.Stringer {
	json := gabs.New()

	// https://github.com/google/gopacket/blob/master/layers/udp.go#L17-L25

	json.SetP(udp.Checksum, "L4.checksum")
	json.SetP(udp.Length, "L4.len")

	json.SetP(udp.SrcPort, "L4.src.port")
	if name, ok := layers.UDPPortNames[udp.SrcPort]; ok {
		json.SetP(name, "L4.src.proto")
	}

	json.SetP(udp.DstPort, "L4.dst.port")
	if name, ok := layers.UDPPortNames[udp.DstPort]; ok {
		json.SetP(name, "L4.dst.proto")
	}

	return json
}

func (t *JSONPcapTranslator) translateTCPLayer(ctx context.Context, tcp *layers.TCP) fmt.Stringer {
	json := gabs.New()

	// https://github.com/google/gopacket/blob/master/layers/tcp.go#L19-L35

	json.SetP(tcp.Seq, "L4.seq")
	json.SetP(tcp.Ack, "L4.ack")
	json.SetP(tcp.DataOffset, "L4.off")
	json.SetP(tcp.Window, "L4.win")
	json.SetP(tcp.Checksum, "L4.checksum")
	json.SetP(tcp.Urgent, "L4.urg")
	json.SetP(tcp.SYN, "L4.flags.SYN")
	json.SetP(tcp.ACK, "L4.flags.ACK")
	json.SetP(tcp.PSH, "L4.flags.PSH")
	json.SetP(tcp.FIN, "L4.flags.FIN")
	json.SetP(tcp.RST, "L4.flags.RST")
	json.SetP(tcp.URG, "L4.flags.URG")
	json.SetP(tcp.ECE, "L4.flags.ECE")
	json.SetP(tcp.CWR, "L4.flags.CWR")
	json.SetP(tcp.NS, "L4.flags.NS")

	r := regexp.MustCompile(`^TCPOption\((?P<opt>.*?)\)$`)
	for _, opt := range tcp.Options {
		if o := r.FindStringSubmatch(opt.String()); o != nil {
			json.ArrayAppendP(o[1], "L4.opts")
		}
	}

	json.SetP(tcp.SrcPort, "L4.src.port")
	if name, ok := layers.TCPPortNames[tcp.SrcPort]; ok {
		json.SetP(name, "L4.src.proto")
	}

	json.SetP(tcp.DstPort, "L4.dst.port")
	if name, ok := layers.TCPPortNames[tcp.DstPort]; ok {
		json.SetP(name, "L4.dst.proto")
	}

	return json
}

func (t *JSONPcapTranslator) merge(ctx context.Context, tgt fmt.Stringer, src fmt.Stringer) (fmt.Stringer, error) {
	return tgt, t.asTranslation(tgt).Merge(t.asTranslation(src))
}

func newJSONPcapTranslator() *JSONPcapTranslator {
	var ifaces sync.Map
	return &JSONPcapTranslator{ifaces}
}
