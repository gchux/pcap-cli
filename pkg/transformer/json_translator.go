package transformer

import (
	"context"
	"fmt"
	"net"
	"regexp"
	"strings"

	"github.com/Jeffail/gabs/v2"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type JSONPcapTranslator struct {
	iface *PcapIface
}

func (t *JSONPcapTranslator) translate(packet *gopacket.Packet) error {
	return fmt.Errorf("not implemented")
}

// return pointer to `struct` `gabs.Container`
func (t *JSONPcapTranslator) next(ctx context.Context, packet *gopacket.Packet, serial *uint64) fmt.Stringer {
	json := gabs.New()

	json.SetP(ctx.Value(ContextLogName), "logName")

	json.SetP(ctx.Value(ContextID), "pcap.ctx")
	json.SetP(*serial, "pcap.num")

	metadata := (*packet).Metadata()
	info := metadata.CaptureInfo

	json.SetP(metadata.Truncated, "meta.trunc")
	json.SetP(info.Length, "meta.len")
	json.SetP(info.CaptureLength, "meta.cap_len")

	json.SetP(info.Timestamp, "timestamp.str")
	json.SetP(info.Timestamp.UnixMicro(), "timestamp.usec")

	json.SetP(t.iface.Index, "iface.index")
	json.SetP(t.iface.Name, "iface.name")
	json.ArrayP("iface.addrs")
	for _, addr := range t.iface.Addrs {
		json.ArrayAppendP(addr.IP.String(), "iface.addrs")
	}

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
	for _, opt := range ip.Options {
		o := gabs.New()
		o.Set(string(opt.OptionData), "data")
		o.Set(opt.OptionType, "type")
		json.ArrayAppendP(0, "opts")
	}

	json.SetP(ip.Protocol, "L3.proto.num")
	json.SetP(ip.Protocol.String(), "L3.proto.name")

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

	json.SetP(udp.SrcPort, "L4.src")
	if name, ok := layers.UDPPortNames[udp.SrcPort]; ok {
		json.SetP(name, "L4.sproto")
	}

	json.SetP(udp.DstPort, "L4.dst")
	if name, ok := layers.UDPPortNames[udp.DstPort]; ok {
		json.SetP(name, "L4.dproto")
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

	json.SetP(tcp.SrcPort, "L4.src")
	if name, ok := layers.TCPPortNames[tcp.SrcPort]; ok {
		json.SetP(name, "L4.sproto")
	}

	json.SetP(tcp.DstPort, "L4.dst")
	if name, ok := layers.TCPPortNames[tcp.DstPort]; ok {
		json.SetP(name, "L4.dproto")
	}

	return json
}

func (t *JSONPcapTranslator) translateTLSLayer(ctx context.Context, tls *layers.TLS) fmt.Stringer {
	json := gabs.New()

	t.decodeTLSRecords(1, tls.Contents, json)

	if len(tls.ChangeCipherSpec) > 0 {
		t.translateTLSLayer_ChangeCipherSpec(ctx, json, tls)
	}

	if len(tls.Handshake) > 0 {
		t.translateTLSLayer_Handshake(ctx, json, tls)
	}

	if len(tls.AppData) > 0 {
		t.translateTLSLayer_AppData(ctx, json, tls)
	}

	return json
}

func (t *JSONPcapTranslator) translateDNSLayer(ctx context.Context, dns *layers.DNS) fmt.Stringer {
	json := gabs.New()

	json.SetP(dns.ID, "DNS.id")
	json.SetP(dns.OpCode.String(), "DNS.op")
	json.SetP(dns.ResponseCode.String(), "DNS.response_code")

	/*
		json.SetP(dns.QR, "DNS.QR")
		json.SetP(dns.AA, "DNS.AA")
		json.SetP(dns.TC, "DNS.TC")
		json.SetP(dns.RD, "DNS.RD")
		json.SetP(dns.RA, "DNS.RA")
	*/

	json.SetP(dns.QDCount, "DNS.questions_count")
	json.SetP(dns.ANCount, "DNS.answers_count")
	/*
		json.SetP(dns.NSCount, "DNS.authorities_count")
		json.SetP(dns.ARCount, "DNS.additionals_count")
	*/

	for _, question := range dns.Questions {
		q := gabs.New()
		q.Set(string(question.Name), "name")
		q.Set(question.Type.String(), "type")
		q.Set(question.Class.String(), "class")
		json.ArrayAppendP(q, "DNS.questions")
	}

	for _, answer := range dns.Answers {
		a := gabs.New()

		// Header
		a.Set(string(answer.Name), "name")
		a.Set(answer.Type.String(), "type")
		a.Set(answer.Class.String(), "class")
		a.Set(answer.TTL, "ttl")

		if answer.IP != nil {
			a.Set(answer.IP.String(), "ip")
		}

		if answer.NS != nil && len(answer.NS) > 0 {
			a.Set(string(answer.NS), "ns")
		}

		if answer.CNAME != nil && len(answer.CNAME) > 0 {
			a.Set(string(answer.CNAME), "cname")
		}

		if answer.PTR != nil && len(answer.PTR) > 0 {
			a.Set(string(answer.PTR), "ptr")
		}

		for _, txt := range answer.TXTs {
			a.ArrayAppendP(string(txt), "txt")
		}

		/*
			a.SetP(string(answer.SOA.MName), "soa.mname")
			a.SetP(string(answer.SOA.RName), "soa.rname")
			a.SetP(answer.SOA.Serial, "soa.serial")
			a.SetP(answer.SOA.Expire, "soa.expire")
			a.SetP(answer.SOA.Refresh, "soa.refresh")
			a.SetP(answer.SOA.Retry, "soa.retry")

			a.SetP(string(answer.SRV.Name), "srv.name")
			a.SetP(answer.SRV.Port, "srv.port")
			a.SetP(answer.SRV.Weight, "srv.weight")
			a.SetP(answer.SRV.Priority, "srv.priority")

			a.SetP(string(answer.MX.Name), "mx.name")
			a.SetP(answer.MX.Preference, "mx.preference")

			a.SetP(string(answer.URI.Target), "uri.target")
			a.SetP(answer.URI.Priority, "uri.priority")
			a.SetP(answer.URI.Weight, "uri.weight")
		*/

		for _, opt := range answer.OPT {
			o := gabs.New()
			o.Set(opt.Code.String(), "code")
			o.Set(string(opt.Data), "data")
			a.ArrayAppendP(o, "opts")
		}

		json.ArrayAppendP(a, "DNS.answers")
	}

	return json
}

func (t *JSONPcapTranslator) merge(ctx context.Context, tgt fmt.Stringer, src fmt.Stringer) (fmt.Stringer, error) {
	return tgt, t.asTranslation(tgt).Merge(t.asTranslation(src))
}

func (t *JSONPcapTranslator) finalize(ctx context.Context, packet fmt.Stringer) (fmt.Stringer, error) {
	json := t.asTranslation(packet)

	serial, _ := json.Path("pcap.num").Data().(uint64)
	iface, _ := json.Path("iface.name").Data().(string)

	l3Src, _ := json.Path("L3.src").Data().(net.IP)
	l3Dst, _ := json.Path("L3.dst").Data().(net.IP)

	message := fmt.Sprintf("#:%d | @:%s | %%s | %%s/%s:%%d > %%s/%s:%%d", serial, iface, l3Src, l3Dst)

	proto := json.Path("L3.proto.num").Data().(layers.IPProtocol)
	isTCP := proto == layers.IPProtocolTCP
	isUDP := proto == layers.IPProtocolUDP

	if !isTCP && !isUDP {
		json.Set(fmt.Sprintf(message, proto.String(), "", 0, "", 0), "message")
		return json, nil
	}

	l4SrcProto, _ := json.Path("L4.sproto").Data().(string)
	l4DstProto, _ := json.Path("L4.dproto").Data().(string)

	if isUDP {
		srcPort, _ := json.Path("L4.src").Data().(layers.UDPPort)
		dstPort, _ := json.Path("L4.dst").Data().(layers.UDPPort)
		json.Set(fmt.Sprintf(message, "UDP", l4SrcProto, srcPort, l4DstProto, dstPort), "message")
		return json, nil
	}

	srcPort, _ := json.Path("L4.src").Data().(layers.TCPPort)
	dstPort, _ := json.Path("L4.dst").Data().(layers.TCPPort)
	message = fmt.Sprintf(message, "TCP", l4SrcProto, srcPort, l4DstProto, dstPort)

	flags := make([]string, 0, len(tcpFlagNames))
	for _, flagName := range tcpFlagNames {
		if isSet, _ := json.Path(`L4.flags.` + flagName).Data().(bool); isSet {
			flags = append(flags, flagName)
		}
	}

	seq, _ := json.Path("L4.seq").Data().(uint32)
	ack, _ := json.Path("L4.ack").Data().(uint32)

	json.Set(fmt.Sprintf("%s | [%s] | seq:%d | ack:%d", message, strings.Join(flags, "|"), seq, ack), "message")
	return json, nil
}

func newJSONPcapTranslator(iface *PcapIface) *JSONPcapTranslator {
	return &JSONPcapTranslator{iface: iface}
}
