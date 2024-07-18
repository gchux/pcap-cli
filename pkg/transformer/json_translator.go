package transformer

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Jeffail/gabs/v2"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/pkg/errors"
	"github.com/segmentio/fasthash/fnv1a"
	"github.com/wissance/stringFormatter"

	mapset "github.com/deckarep/golang-set/v2"
	csmap "github.com/mhmtszr/concurrent-swiss-map"
	"github.com/zhangyunhao116/skipmap"
)

type (
	JSONPcapTranslator struct {
		mu                    sync.Mutex
		iface                 *PcapIface
		traceToHttpRequestMap *csmap.CsMap[string, *httpRequest]
		flowsWithTrace        mapset.Set[uint64]
		halfOpenFlows         mapset.Set[uint64]
		establishedFlows      mapset.Set[uint64]
		halfClosedFlows       mapset.Set[uint64]
		flowToTimestamp       *csmap.CsMap[uint64, *time.Time]
		flowToSequenceMap     *csmap.CsMap[uint64, *skipmap.Uint32Map[*traceAndSpan]]
	}
)

const (
	jsonTranslationSummary          = "#:{serial} | @:{ifaceIndex}/{ifaceName} | flow:{flowID} | "
	jsonTranslationSummaryWithoutL4 = jsonTranslationSummary + "{L3Src} > {L3Dst}"
	jsonTranslationSummaryUDP       = jsonTranslationSummary + "{L4Proto} | {srcProto}/{L3Src}:{L4Src} > {dstProto}/{L3Dst}:{L4Dst}"
	jsonTranslationSummaryTCP       = jsonTranslationSummaryUDP + " | [{tcpFlags}] | seq/ack:{tcpSeq}/{tcpAck}"
	jsonTranslationFlowTemplate     = "{0}/iface/{1}/flow/{2}:{3}"
)

func (t *JSONPcapTranslator) translate(packet *gopacket.Packet) error {
	return fmt.Errorf("not implemented")
}

// return pointer to `struct` `gabs.Container`
func (t *JSONPcapTranslator) next(ctx context.Context, serial *uint64, packet *gopacket.Packet) fmt.Stringer {
	json := gabs.New()

	id := ctx.Value(ContextID)
	logName := ctx.Value(ContextLogName)

	pcap, _ := json.Object("pcap")
	pcap.Set(id, "id")
	pcap.Set(logName, "ctx")
	pcap.Set(*serial, "num")

	metadata := (*packet).Metadata()
	info := metadata.CaptureInfo

	meta, _ := json.Object("meta")
	meta.Set(metadata.Truncated, "trunc")
	meta.Set(info.Length, "len")
	meta.Set(info.CaptureLength, "cap_len")

	metaTimestamp, _ := meta.Object("timestamp")
	metaTimestamp.Set(info.Timestamp.String(), "str")
	metaTimestamp.Set(info.Timestamp.UnixNano())

	timestamp, _ := json.Object("timestamp")
	timestamp.Set(info.Timestamp.Unix(), "seconds")
	timestamp.Set(info.Timestamp.Nanosecond(), "nanos")

	iface, _ := json.Object("iface")
	iface.Set(t.iface.Index, "index")
	iface.Set(t.iface.Name, "name")
	addrs, _ := iface.ArrayOfSize(len(t.iface.Addrs), "addrs")
	for i, addr := range t.iface.Addrs {
		addrs.SetIndex(addr.IP.String(), i)
	}

	json.Set(fnv1a.AddUint64(fnv1a.Init64, uint64(t.iface.Index)), "flow")

	labels, _ := json.Object("logging.googleapis.com/labels")
	labels.Set("pcap", "tools.chux.dev/tool")
	labels.Set(id, "tools.chux.dev/pcap/id")
	labels.Set(logName, "tools.chux.dev/pcap/name")
	labels.Set(t.iface.Name, "tools.chux.dev/pcap/iface")

	return json
}

func (t *JSONPcapTranslator) asTranslation(buffer fmt.Stringer) *gabs.Container {
	return buffer.(*gabs.Container)
}

func (t *JSONPcapTranslator) translateEthernetLayer(ctx context.Context, eth *layers.Ethernet) fmt.Stringer {
	json := gabs.New()

	L2, _ := json.Object("L2")
	L2.Set(eth.EthernetType.String(), "type")
	L2.Set(eth.SrcMAC.String(), "src")
	L2.Set(eth.DstMAC.String(), "dst")

	return json
}

func (t *JSONPcapTranslator) translateIPv4Layer(ctx context.Context, ip *layers.IPv4) fmt.Stringer {
	json := gabs.New()

	// https://github.com/google/gopacket/blob/master/layers/ip4.go#L43

	L3, _ := json.Object("L3")
	L3.Set(ip.Version, "v")
	L3.Set(ip.SrcIP, "src")
	L3.Set(ip.DstIP, "dst")
	L3.Set(ip.Id, "id")
	L3.Set(ip.IHL, "ihl")
	L3.Set(ip.TTL, "ttl")
	L3.Set(ip.TOS, "tos")
	L3.Set(ip.Length, "len")
	L3.Set(ip.FragOffset, "frag_offset")
	L3.Set(ip.Checksum, "checksum")

	opts, _ := L3.ArrayOfSize(len(ip.Options), "opts")
	for i, opt := range ip.Options {
		o, _ := opts.ObjectI(i)
		o.Set(string(opt.OptionData), "data")
		o.Set(opt.OptionType, "type")
	}

	proto, _ := L3.Object("proto")
	proto.Set(ip.Protocol, "num")
	proto.Set(ip.Protocol.String(), "name")
	// https://github.com/google/gopacket/blob/master/layers/ip4.go#L28-L40
	L3.SetP(strings.Split(ip.Flags.String(), "|"), "flags")

	// hashing bytes yields `uint64`, and addition is commutatie:
	//   - so hashing the IP byte array representations and then adding then resulting `uint64`s is a commutative operation as well.
	L3.Set(fnv1a.HashUint64(4+fnv1a.HashBytes64(ip.SrcIP.To4())+fnv1a.HashBytes64(ip.DstIP.To4())), "flow") // IPv4(4) (0x04)

	return json
}

func (t *JSONPcapTranslator) translateIPv6Layer(ctx context.Context, ip *layers.IPv6) fmt.Stringer {
	json := gabs.New()

	// https://github.com/google/gopacket/blob/master/layers/ip6.go#L28-L43

	L3, _ := json.Object("L3")
	L3.Set(ip.Version, "v")
	L3.Set(ip.SrcIP, "src")
	L3.Set(ip.DstIP, "dst")
	L3.Set(ip.Length, "len")
	L3.Set(ip.TrafficClass, "traffic_class")
	L3.Set(ip.FlowLabel, "flow_label")
	L3.Set(ip.HopLimit, "hop_limit")

	proto, _ := L3.Object("proto")
	proto.Set(ip.NextHeader, "num")
	proto.Set(ip.NextHeader.String(), "name")

	// hashing bytes yields `uint64`, and addition is commutatie:
	//   - so hashing the IP byte array representations and then adding then resulting `uint64`s is a commutative operation as well.
	L3.Set(fnv1a.HashUint64(41+fnv1a.HashBytes64(ip.SrcIP.To16())+fnv1a.HashBytes64(ip.DstIP.To16())), "flow") // IPv6(41) (0x29)

	// missing `HopByHop`: https://github.com/google/gopacket/blob/master/layers/ip6.go#L40
	return json
}

func (t *JSONPcapTranslator) translateUDPLayer(ctx context.Context, udp *layers.UDP) fmt.Stringer {
	json := gabs.New()

	// https://github.com/google/gopacket/blob/master/layers/udp.go#L17-L25

	L4, _ := json.Object("L4")

	L4.Set(udp.Checksum, "checksum")
	L4.Set(udp.Length, "len")

	L4.Set(udp.SrcPort, "src")
	if name, ok := layers.UDPPortNames[udp.SrcPort]; ok {
		L4.Set(name, "sproto")
	}

	L4.SetP(udp.DstPort, "dst")
	if name, ok := layers.UDPPortNames[udp.DstPort]; ok {
		L4.Set(name, "dproto")
	}

	// `SrcPort` and `DstPort` are `uint8`
	L4.Set(fnv1a.HashUint64(17+uint64(udp.SrcPort)+uint64(udp.DstPort)), "flow") // UDP(17) (0x11)

	return json
}

func (t *JSONPcapTranslator) translateTCPLayer(ctx context.Context, tcp *layers.TCP) fmt.Stringer {
	json := gabs.New()

	// https://github.com/google/gopacket/blob/master/layers/tcp.go#L19-L35

	L4, _ := json.Object("L4")

	L4.Set(tcp.Seq, "seq")
	L4.Set(tcp.Ack, "ack")
	L4.Set(tcp.DataOffset, "off")
	L4.Set(tcp.Window, "win")
	L4.Set(tcp.Checksum, "checksum")
	L4.Set(tcp.Urgent, "urg")

	var setFlags uint8 = 0

	flags, _ := L4.Object("flags")

	flagsMap, _ := flags.Object("map")
	flagsMap.Set(tcp.SYN, "SYN")
	if tcp.SYN {
		setFlags = setFlags | tcpSyn
	}
	flagsMap.Set(tcp.ACK, "ACK")
	if tcp.ACK {
		setFlags = setFlags | tcpAck
	}
	flagsMap.Set(tcp.PSH, "PSH")
	if tcp.PSH {
		setFlags = setFlags | tcpPsh
	}
	flagsMap.Set(tcp.FIN, "FIN")
	if tcp.FIN {
		setFlags = setFlags | tcpFin
	}
	flagsMap.Set(tcp.RST, "RST")
	if tcp.RST {
		setFlags = setFlags | tcpRst
	}
	flagsMap.Set(tcp.URG, "URG")
	if tcp.URG {
		setFlags = setFlags | tcpUrg
	}
	flagsMap.Set(tcp.ECE, "ECE")
	flagsMap.Set(tcp.CWR, "CWR")
	flagsMap.Set(tcp.NS, "NS")

	flags.Set(setFlags, "dec")
	flags.Set("0b"+strconv.FormatUint(uint64(setFlags), 2), "bin")
	flags.Set("0x"+strconv.FormatUint(uint64(setFlags), 16), "hex")

	opts, _ := L4.ArrayOfSize(len(tcp.Options), "opts")
	for i, opt := range tcp.Options {
		// Regex'ing TCP options is expensive
		// [TODO]: find a way to not use `regexp` to extract TCP options
		if o := tcpOptionRgx.FindStringSubmatch(opt.String()); o != nil {
			opts.SetIndex(o[1], i)
		}
	}

	L4.Set(tcp.SrcPort, "src")
	if name, ok := layers.TCPPortNames[tcp.SrcPort]; ok {
		L4.Set(name, "sproto")
	}

	L4.Set(tcp.DstPort, "dst")
	if name, ok := layers.TCPPortNames[tcp.DstPort]; ok {
		L4.Set(name, "dproto")
	}

	// `SrcPort` and `DstPort` are `uint8`
	L4.Set(fnv1a.HashUint64(6+uint64(tcp.SrcPort)+uint64(tcp.DstPort)), "flow") // TCP(6) (0x06)

	return json
}

func (t *JSONPcapTranslator) translateTLSLayer(ctx context.Context, tls *layers.TLS) fmt.Stringer {
	json := gabs.New()

	TLS, _ := json.Object("TLS")

	// disabled until memory leak is fixed
	// [TODO]: fix memory leak...
	// t.decodeTLSRecords(1, tls.Contents, TLS)

	if len(tls.ChangeCipherSpec) > 0 {
		t.translateTLSLayer_ChangeCipherSpec(ctx, TLS, tls)
	}

	if len(tls.Handshake) > 0 {
		t.translateTLSLayer_Handshake(ctx, TLS, tls)
	}

	if len(tls.AppData) > 0 {
		t.translateTLSLayer_AppData(ctx, TLS, tls)
	}

	return json
}

func (t *JSONPcapTranslator) translateDNSLayer(ctx context.Context, dns *layers.DNS) fmt.Stringer {
	json := gabs.New()

	domain, _ := json.Object("DNS")
	domain.Set(dns.ID, "id")
	domain.Set(dns.OpCode.String(), "op")
	domain.Set(dns.ResponseCode.String(), "response_code")

	/*
		json.SetP(dns.QR, "DNS.QR")
		json.SetP(dns.AA, "DNS.AA")
		json.SetP(dns.TC, "DNS.TC")
		json.SetP(dns.RD, "DNS.RD")
		json.SetP(dns.RA, "DNS.RA")
	*/

	domain.Set(dns.QDCount, "questions_count")
	domain.Set(dns.ANCount, "answers_count")
	/*
		json.SetP(dns.NSCount, "DNS.authorities_count")
		json.SetP(dns.ARCount, "DNS.additionals_count")
	*/

	questions, _ := domain.ArrayOfSize(len(dns.Questions), "questions")
	for i, question := range dns.Questions {
		q, _ := questions.ObjectI(i)
		q.Set(string(question.Name), "name")
		q.Set(question.Type.String(), "type")
		q.Set(question.Class.String(), "class")
	}

	answers, _ := domain.ArrayOfSize(len(dns.Answers), "answers")
	for i, answer := range dns.Answers {
		a, _ := answers.ObjectI(i)

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

		txts, _ := a.ArrayOfSize(len(answer.TXTs))
		for i, txt := range answer.TXTs {
			txts.SetIndex(string(txt), i)
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

		opts, _ := a.ArrayOfSize(len(answer.OPT), "opt")
		for i, opt := range answer.OPT {
			o, _ := opts.ObjectI(i)
			o.Set(opt.Code.String(), "code")
			o.Set(string(opt.Data), "data")
		}
	}

	return json
}

func (t *JSONPcapTranslator) merge(ctx context.Context, tgt fmt.Stringer, src fmt.Stringer) (fmt.Stringer, error) {
	return tgt, t.asTranslation(tgt).Merge(t.asTranslation(src))
}

// for JSON translator, this mmethod generates:
//   - the `flowID` for any 6-tuple conversation
//   - the summary line at {`message`: $summary}
func (t *JSONPcapTranslator) finalize(
	ctx context.Context,
	serial *uint64,
	p *gopacket.Packet,
	connTrack bool,
	packet fmt.Stringer,
) (fmt.Stringer, error) {
	json := t.asTranslation(packet)

	data := make(map[string]any, 14)

	id := ctx.Value(ContextID)
	logName := ctx.Value(ContextLogName)

	operation, _ := json.Object("logging.googleapis.com/operation")
	operation.Set(logName, "producer")
	if *serial == 1 {
		operation.Set(true, "first")
	}

	data["ifaceIndex"] = t.iface.Index
	data["ifaceName"] = t.iface.Name

	data["serial"] = *serial

	l3Src, _ := json.Path("L3.src").Data().(net.IP)
	data["L3Src"] = l3Src
	l3Dst, _ := json.Path("L3.dst").Data().(net.IP)
	data["L3Dst"] = l3Dst

	proto := json.Path("L3.proto.num").Data().(layers.IPProtocol)
	isTCP := proto == layers.IPProtocolTCP
	isUDP := proto == layers.IPProtocolUDP

	// `flowID` is the unique ID of this conversation:
	// given by the 6-tuple: iface_index+protocol+src_ip+src_port+dst_ip+dst_port.
	// Addition is commutative, so after hashing `net.IP` bytes and L4 ports to `uint64`,
	// the same `uint64`/`flowID` is produced after adding everything up, no matter the order.
	// Using the same `flowID` will produce grouped logs in Cloud Logging.
	flowID, _ := json.Path("flow").Data().(uint64) // this is always available
	if l3FlowID, l3OK := json.Path("L3.flow").Data().(uint64); l3OK {
		flowID = fnv1a.AddUint64(flowID, l3FlowID)
	}
	if l4FlowID, l4OK := json.Path("L4.flow").Data().(uint64); l4OK {
		flowID = fnv1a.AddUint64(flowID, l4FlowID)
	} else {
		flowID = fnv1a.AddUint64(flowID, 255) // RESERVED (0xFF)
	}

	data["flowID"] = flowID
	json.Set(flowID, "flow")

	if !isTCP && !isUDP {
		operation.Set(stringFormatter.Format(jsonTranslationFlowTemplate, id, t.iface.Name, "x", flowID), "id")
		json.Set(stringFormatter.FormatComplex(jsonTranslationSummaryWithoutL4, data), "message")
		return json, nil
	}

	l4SrcProto, _ := json.Path("L4.sproto").Data().(string)
	data["srcProto"] = l4SrcProto

	l4DstProto, _ := json.Path("L4.dproto").Data().(string)
	data["dstProto"] = l4DstProto

	if isUDP {
		data["L4Proto"] = "UDP"
		srcPort, _ := json.Path("L4.src").Data().(layers.UDPPort)
		data["L4Src"] = uint16(srcPort)
		dstPort, _ := json.Path("L4.dst").Data().(layers.UDPPort)
		data["L4Dst"] = uint16(dstPort)
		operation.Set(stringFormatter.Format(jsonTranslationFlowTemplate, id, t.iface.Name, "udp", flowID), "id")
		json.Set(stringFormatter.FormatComplex(jsonTranslationSummaryUDP, data), "message")
		return json, nil
	}

	data["L4Proto"] = "TCP"
	srcPort, _ := json.Path("L4.src").Data().(layers.TCPPort)
	data["L4Src"] = uint16(srcPort)
	dstPort, _ := json.Path("L4.dst").Data().(layers.TCPPort)
	data["L4Dst"] = uint16(dstPort)

	operation.Set(stringFormatter.Format(jsonTranslationFlowTemplate, id, t.iface.Name, "tcp", flowID), "id")

	setFlags, _ := json.Path("L4.flags.dec").Data().(uint8)

	if connTrack {
		t.trackConnection(p, &flowID, &setFlags, json)
	}

	if setFlagsStr, ok := tcpFlagsStr[setFlags]; ok {
		data["tcpFlags"] = setFlagsStr
	} else {
		// this scenario is slow, but it should also be exceedingly rare
		flags := make([]string, 0, len(tcpFlags))
		for key := range tcpFlags {
			if isSet, _ := json.Path(`L4.flags.` + key).Data().(bool); isSet {
				flags = append(flags, key)
			}
		}
		data["tcpFlags"] = strings.Join(flags, "|")
	}

	seq, _ := json.Path("L4.seq").Data().(uint32)
	data["tcpSeq"] = seq
	ack, _ := json.Path("L4.ack").Data().(uint32)
	data["tcpAck"] = ack

	message := stringFormatter.FormatComplex(jsonTranslationSummaryTCP, data)

	appLayer := (*p).ApplicationLayer()
	if setFlags == tcpPshAck && appLayer != nil {
		if !t.trySetHTTP11(p, &setFlags, &appLayer, &flowID, &seq, json, &message) {
			t.trySetTraceAndSpan(json, &flowID, &seq)
		}
	} else {
		t.trySetTraceAndSpan(json, &flowID, &seq)
	}

	if setFlags == tcpFinAck || setFlags == tcpRst {
		t.untrackFlowID(&flowID)
	}

	json.Set(message, "message")
	return json, nil
}

func (t *JSONPcapTranslator) trackConnection(packet *gopacket.Packet, flowID *uint64, flags *uint8, json *gabs.Container) {
	fl := *flags
	fid := *flowID

	shouldRemoveTracking := false
	if fl == tcpSyn && !t.halfOpenFlows.Contains(fid) {
		// TCP 3-way-handshake 1st step
		t.halfOpenFlows.Add(fid)
		json.Set("new connection", "hint")
	} else if fl == tcpSyn && t.halfOpenFlows.Contains(fid) {
		json.Set("duplicate SYN", "hint")
	} else if fl == tcpSynAck && t.halfOpenFlows.Contains(fid) {
		// TCP 3-way-handshake 2nd step
		t.halfOpenFlows.Remove(fid)
		t.establishedFlows.Add(fid)
		json.Set("connection established", "hint")
	} else if fl == tcpFinAck && t.establishedFlows.Contains(fid) {
		t.establishedFlows.Remove(fid)
		t.halfClosedFlows.Add(fid)
		json.Set("closing connection", "hint")
	} else if fl == tcpFinAck && t.halfClosedFlows.Contains(fid) {
		t.halfClosedFlows.Remove(fid)
		shouldRemoveTracking = true
		json.Set("connection closed", "hint")
	} else if fl == tcpRst && t.halfOpenFlows.Contains(fid) {
		t.halfOpenFlows.Remove(fid)
		shouldRemoveTracking = true
		json.Set("connection timeout", "hint")
	} else if fl == tcpRst && t.establishedFlows.Contains(fid) {
		t.establishedFlows.Remove(fid)
		shouldRemoveTracking = true
		json.Set("connection reset", "hint")
	}

	timestamp := (*packet).Metadata().Timestamp
	if ts, ok := t.flowToTimestamp.Load(fid); ok {
		json.Set(timestamp.Sub(*ts).Milliseconds(), "latency")
		t.flowToTimestamp.Store(fid, &timestamp)
	} else {
		t.flowToTimestamp.SetIfAbsent(fid, &timestamp)
	}

	if shouldRemoveTracking {
		t.flowToTimestamp.Delete(fid)
		go t.untrackFlowID(flowID)
	}
}

func (t *JSONPcapTranslator) untrackFlowID(flowID *uint64) bool {
	if ftsm, ok := t.flowToSequenceMap.Load(*flowID); ok {
		sequences := make([]uint32, ftsm.Len())
		index := 0
		ftsm.Range(func(sequence uint32, _ *traceAndSpan) bool {
			sequences[index] = sequence
			return true
		})
		for sequence := range sequences {
			ftsm.Delete(uint32(sequence))
		}
		t.flowsWithTrace.Remove(*flowID)
		return t.flowToSequenceMap.Delete(*flowID)
	}
	return false
}

func (t *JSONPcapTranslator) trySetTraceAndSpan(json *gabs.Container, flowID *uint64, sequence *uint32) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	sequenceToTraceMap, ok := t.flowToSequenceMap.Load(*flowID)

	// no HTTP/1.1 request with a `traceID` has been seen for this `flowID`
	if !ok { // it is also possible that packet for HTTP request for this `flowID`
		return false
	}

	// an HTTP/1.1 request with a `traceID` has already been seen for this `flowID`
	var ts, lastTS *traceAndSpan = nil, nil
	sequenceToTraceMap.Range(func(key uint32, value *traceAndSpan) bool {
		// Loop over the map keys (sequence numbers) until one greater than `sequence` is found.
		// HTTP/1.1 is not multiplexed, so a new request using the same TCP connection ( i/e: pooling )
		// should be observed (alongside its `traceID`) with a higher sequence number than the previous one;
		// when the key (a sequence number) is greater than the current one, stop looping;
		// the previously analyzed `key` (sequence number) must be pointing to the correct `traceID`.
		// TL;DR: `traceID`s exist within a specific TCP sequence range which configure a boundary.
		isSequenceGreaterThanKey := *sequence > key
		if isSequenceGreaterThanKey {
			ts = value
		}
		lastTS = value
		return true
	})

	// TCP sequence number is `uint32` so it is possible
	// for for it to be rolled over if it gets too big.
	// In such case `sequence` was not greater than any `key` in the map,
	// so the last visited `key` must be pointing to the correct `traceID`
	if ts == nil {
		ts = lastTS
	}

	t.setTraceAndSpan(json, ts.traceID, ts.spanID)

	return true
}

func (t *JSONPcapTranslator) trySetHTTP11(
	packet *gopacket.Packet,
	tcpFlags *uint8,
	appLayer *gopacket.ApplicationLayer,
	flowID *uint64,
	sequence *uint32,
	json *gabs.Container,
	message *string,
) bool {
	appLayerData := (*appLayer).LayerContents()

	isHTTP11Request := http11RequestPayloadRegex.Match(appLayerData)
	isHTTP11Response := !isHTTP11Request && http11ResponsePayloadRegex.Match(appLayerData)

	// if content is not HTTP in clear text, abort
	if !isHTTP11Request && !isHTTP11Response {
		json.Set(*message, "message")
		return false
	}
	// making at least 1 big assumption:
	//   HTTP request/status line and headers fit in 1 packet
	//     which is not always the case when fragmentation occurs
	L7, _ := json.Object("L7")

	httpDataReader := bufio.NewReaderSize(bytes.NewReader(appLayerData), len(appLayerData))

	// attempt to parse HTTP/1.1 request
	if isHTTP11Request {
		request, err := http.ReadRequest(httpDataReader)
		if err == nil {
			L7.Set("request", "kind")
			url := request.URL.String()
			L7.Set(url, "url")
			L7.Set(request.Proto, "proto")
			L7.Set(request.Method, "method")
			if traceAndSpan := t.setHTTPHeaders(L7, &request.Header); traceAndSpan != nil {
				t.flowsWithTrace.Add(*flowID)
				// include trace and span id for traceability
				t.setTraceAndSpan(json, &traceAndSpan[0], &traceAndSpan[1])
				t.recordHTTP11Request(packet, flowID, sequence, &traceAndSpan[0], &traceAndSpan[1], &request.Method, &request.Host, &url)
			}
			json.Set(stringFormatter.Format("{0} | {1} {2} {3}", *message, request.Proto, request.Method, url), "message")
			return true
		}
	}

	// attempt to parse HTTP/1.1 response
	if isHTTP11Response {
		response, err := http.ReadResponse(httpDataReader, nil)
		if err == nil {
			L7.Set("response", "kind")
			L7.Set(response.Proto, "proto")
			L7.Set(response.StatusCode, "code")
			L7.Set(response.Status, "status")
			if traceAndSpan := t.setHTTPHeaders(L7, &response.Header); traceAndSpan != nil {
				// include trace and span id for traceability
				t.setTraceAndSpan(json, &traceAndSpan[0], &traceAndSpan[1])
				if err := t.linkHTTP11ResponseToRequest(packet, tcpFlags, flowID, L7, &traceAndSpan[0]); err != nil {
					io.WriteString(os.Stderr, err.Error())
				}
			}
			json.Set(stringFormatter.Format("{0} | {1} {2}", *message, response.Proto, response.Status), "message")
			return true
		}
	}

	// fallback to a minimal (naive) attempt to parse HTTP/1.1
	//   - intentionally dropping HTTP request/response payload
	// see: https://www.rfc-editor.org/rfc/rfc7540#section-8.1.3
	dataBytes := bytes.SplitN(appLayerData, http11BodySeparator, 2)[0]
	parts := bytes.Split(dataBytes, http11Separator)

	var traceAndSpan []string = nil

	headers, _ := L7.Object("headers")
	for _, header := range parts[1:] {
		headerParts := bytes.SplitN(header, http11HeaderSeparator, 2)
		value := string(bytes.TrimSpace(headerParts[1]))
		headers.Set(value, string(headerParts[0]))
		// include trace and span id for traceability
		if bytes.EqualFold(parts[0], cloudTraceContextHeaderBytes) {
			if traceAndSpan = t.getTraceAndSpan(&value); traceAndSpan != nil {
				t.setTraceAndSpan(json, &traceAndSpan[0], &traceAndSpan[1])
			}
		}
	}

	line := string(parts[0])
	L7.Set(line, "line")
	json.Set(stringFormatter.Format("{0} | {1}", *message, line), "message")

	if isHTTP11Request {
		requestParts := http11RequestPayloadRegex.FindStringSubmatch(line)
		L7.Set(requestParts[1], "method")
		L7.Set(requestParts[2], "url")
		host := "0"
		if traceAndSpan != nil {
			t.recordHTTP11Request(packet, flowID, sequence, &traceAndSpan[0], &traceAndSpan[1], &requestParts[1], &host, &requestParts[2])
		}
		return true
	}

	// isHTTP11Response
	responseParts := http11ResponsePayloadRegex.FindStringSubmatch(line)
	if code, err := strconv.Atoi(responseParts[1]); err == nil {
		L7.Set(code, "code")
	} else {
		L7.Set(responseParts[1], "code")
	}
	L7.Set(responseParts[2], "status")
	if traceAndSpan != nil {
		if err := t.linkHTTP11ResponseToRequest(packet, tcpFlags, flowID, L7, &traceAndSpan[0]); err != nil {
			io.WriteString(os.Stderr, err.Error())
		}
	}
	return true
}

func (t *JSONPcapTranslator) recordHTTP11Request(packet *gopacket.Packet, flowID *uint64, sequence *uint32, traceID, spanID, method, host, url *string) {
	fullURL := stringFormatter.Format("{0}{1}", *host, *url)
	_httpRequest := &httpRequest{
		timestamp: &(*packet).Metadata().Timestamp,
		method:    method,
		url:       &fullURL,
	}
	// if a response is never seen for this trace id, it will cause a memory leak
	t.traceToHttpRequestMap.SetIfAbsent(*traceID, _httpRequest)

	var sequenceToTraceMap *skipmap.Uint32Map[*traceAndSpan] = nil
	t.mu.Lock()
	if ftsm, ok := t.flowToSequenceMap.Load(*flowID); ok {
		sequenceToTraceMap = ftsm
	} else {
		t.flowsWithTrace.Add(*flowID)
		sequenceToTraceMap = skipmap.NewUint32[*traceAndSpan]()
		t.flowToSequenceMap.Store(*flowID, sequenceToTraceMap)
	}
	// [ToDo]: store a pointer to a `struct` with both: `traceID` and `spanID`
	sequenceToTraceMap.Store(*sequence, &traceAndSpan{traceID, spanID})
	t.mu.Unlock()
}

func (t *JSONPcapTranslator) linkHTTP11ResponseToRequest(packet *gopacket.Packet, flags *uint8, flowID *uint64, response *gabs.Container, traceID *string) error {
	jsonTranslatorRequest, ok := t.traceToHttpRequestMap.Load(*traceID)
	if !ok {
		return errors.New(stringFormatter.Format("no request found for trace-id: {0}", *traceID))
	}

	translatorRequest := *jsonTranslatorRequest
	// hydrate response with information from request
	request, _ := response.Object("request")
	request.Set(*translatorRequest.method, "method")
	request.Set(*translatorRequest.url, "url")
	requestTimestamp := *translatorRequest.timestamp
	responseTimestamp := (*packet).Metadata().Timestamp
	latency := responseTimestamp.Sub(requestTimestamp)
	request.Set(requestTimestamp.String(), "timestamp")
	request.Set(latency.Milliseconds(), "latency")

	if !t.traceToHttpRequestMap.Delete(*traceID) {
		return errors.New(stringFormatter.Format("failed to delete request with trace-id: {0}", *traceID))
	}
	return nil
}

func (t *JSONPcapTranslator) setHTTPHeaders(L7 *gabs.Container, headers *http.Header) []string {
	jsonHeaders, _ := L7.Object("headers")
	var traceAndSpan []string = nil
	for key, value := range *headers {
		jsonHeaders.Set(value, key)
		if strings.EqualFold(key, cloudTraceContextHeader) {
			traceAndSpan = t.getTraceAndSpan(&value[0])
		}
	}
	return traceAndSpan
}

func (t *JSONPcapTranslator) getTraceAndSpan(rawTraceAndSpan *string) []string {
	if traceAndSpan := traceAndSpanRegex.FindStringSubmatch(*rawTraceAndSpan); traceAndSpan != nil {
		return traceAndSpan[1:]
	}
	return nil
}

func (t *JSONPcapTranslator) setTraceAndSpan(json *gabs.Container, trace, span *string) {
	json.Set(cloudTracePrefix+*trace, "logging.googleapis.com/trace")
	json.Set(*span, "logging.googleapis.com/spanId")
	json.Set(true, "logging.googleapis.com/trace_sampled")
}

func (t *JSONPcapTranslator) toJSONBytes(packet *fmt.Stringer) (int, []byte, error) {
	translation, err := t.asTranslation(*packet).MarshalJSON()
	if err != nil {
		return 0, nil, errors.Wrap(err, "JSON translation failed")
	}
	lineBreak := []byte("\n")
	b := make([]byte, len(lineBreak)+len(translation))
	return copy(b[copy(b[0:], translation):], lineBreak), b, nil
}

func (t *JSONPcapTranslator) write(ctx context.Context, writer io.Writer, packet *fmt.Stringer) (int, error) {
	bytesCount, translationBytes, err := t.toJSONBytes(packet)
	if err != nil {
		return 0, errors.Wrap(err, "JSON translation failed")
	}
	writtenBytes, err := writer.Write(translationBytes)
	if err != nil {
		return 0, errors.Wrap(err, "failed to write JSON translation")
	}
	if bytesCount != writtenBytes {
		return writtenBytes, errors.New("translationBytes(" + strconv.Itoa(bytesCount) + ") != writtenBytes(" + strconv.Itoa(writtenBytes) + ")")
	}
	return writtenBytes, nil
}

func newJSONPcapTranslator(iface *PcapIface) *JSONPcapTranslator {
	traceToHttpRequestMap := csmap.Create(
		// set the number of map shards. the default value is 32.
		csmap.WithShardCount[string, *httpRequest](32),
		// if don't set custom hasher, use the built-in maphash.
		csmap.WithCustomHasher[string, *httpRequest](func(key string) uint64 {
			return fnv1a.HashString64(key)
		}),
		// set the total capacity, every shard map has total capacity/shard count capacity. the default value is 0.
		csmap.WithSize[string, *httpRequest](1000),
	)

	flowToTimestamp := csmap.Create[uint64, *time.Time](
		csmap.WithShardCount[uint64, *time.Time](32),
		csmap.WithCustomHasher[uint64, *time.Time](func(key uint64) uint64 { return key }),
		csmap.WithSize[uint64, *time.Time](1000),
	)

	flowsWithTrace := mapset.NewSet[uint64]()
	halfOpenFlows := mapset.NewSet[uint64]()
	halfClosedFlows := mapset.NewSet[uint64]()
	establishedFlows := mapset.NewSet[uint64]()

	flowToSequenceMap := csmap.Create(
		csmap.WithShardCount[uint64, *skipmap.Uint32Map[*traceAndSpan]](32),
		csmap.WithCustomHasher[uint64, *skipmap.Uint32Map[*traceAndSpan]](func(key uint64) uint64 { return key }),
		csmap.WithSize[uint64, *skipmap.Uint32Map[*traceAndSpan]](1000),
	)

	return &JSONPcapTranslator{
		iface:                 iface,
		traceToHttpRequestMap: traceToHttpRequestMap,
		flowToTimestamp:       flowToTimestamp,
		halfOpenFlows:         halfOpenFlows,
		halfClosedFlows:       halfClosedFlows,
		establishedFlows:      establishedFlows,
		flowsWithTrace:        flowsWithTrace,
		flowToSequenceMap:     flowToSequenceMap,
	}
}
