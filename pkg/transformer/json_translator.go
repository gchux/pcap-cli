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
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Jeffail/gabs/v2"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/pkg/errors"
	"github.com/segmentio/fasthash/fnv1a"
	"github.com/wissance/stringFormatter"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"

	"github.com/alphadose/haxmap"
	mapset "github.com/deckarep/golang-set/v2"
)

type (
	JSONPcapTranslator struct {
		fm                        *flowMutex
		iface                     *PcapIface
		traceToHttpRequestMap     *haxmap.Map[string, *httpRequest]
		flowToStreamToSequenceMap FTSTSM
	}
)

const (
	jsonTranslationSummary          = "#:{serial} | @:{ifaceIndex}/{ifaceName} | flow:{flowID} | "
	jsonTranslationSummaryWithoutL4 = jsonTranslationSummary + "{L3Src} > {L3Dst}"
	jsonTranslationSummaryUDP       = jsonTranslationSummary + "{L4Proto} | {srcProto}/{L3Src}:{L4Src} > {dstProto}/{L3Dst}:{L4Dst}"
	jsonTranslationSummaryTCP       = jsonTranslationSummaryUDP + " | [{tcpFlags}] | seq/ack:{tcpSeq}/{tcpAck}"
	jsonTranslationFlowTemplate     = "{0}/iface/{1}/flow/{2}:{3}"
)

const (
	carrierDeadline  = 600 * time.Second /* 10m */
	trackingDeadline = 10 * time.Second  /* 10s */
)

func (t *JSONPcapTranslator) translate(_ *gopacket.Packet) error {
	return fmt.Errorf("not implemented")
}

func (t *JSONPcapTranslator) done(ctx context.Context) {
	t.fm.MutexMap.ForEach(func(flowID uint64, lock *flowLockCarrier) bool {
		if lock.mu.TryLock() {
			t.fm.untrackConnection(ctx, &flowID, lock)
			transformerLogger.Printf("[%d/%s] – untracked flow: %d\n", t.iface.Index, t.iface.Name, flowID)
			lock.mu.Unlock()
		}
		return true
	})
	t.fm.MutexMap.Clear()
	t.flowToStreamToSequenceMap.Clear()
	t.traceToHttpRequestMap.Clear()
}

// return pointer to `struct` `gabs.Container`
func (t *JSONPcapTranslator) next(ctx context.Context, serial *uint64, packet *gopacket.Packet) fmt.Stringer {
	flowID := fnv1a.AddUint64(fnv1a.Init64, uint64(t.iface.Index))
	flowIDstr := strconv.FormatUint(flowID, 10)

	json := gabs.New()

	id := ctx.Value(ContextID)
	logName := ctx.Value(ContextLogName)

	pcap, _ := json.Object("pcap")
	pcap.Set(id, "id")
	pcap.Set(logName, "ctx")

	serialStr := strconv.FormatUint(*serial, 10)
	pcap.Set(serialStr, "num")

	metadata := (*packet).Metadata()
	info := metadata.CaptureInfo

	meta, _ := json.Object("meta")
	meta.Set(metadata.Truncated, "trunc")
	meta.Set(info.Length, "len")
	meta.Set(info.CaptureLength, "cap_len")
	meta.Set(flowIDstr, "flow")
	meta.Set(info.Timestamp.Format(time.RFC3339Nano), "timestamp")

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

func (t *JSONPcapTranslator) translateIPv4Layer(ctx context.Context, ip4 *layers.IPv4) fmt.Stringer {
	json := gabs.New()

	// https://github.com/google/gopacket/blob/master/layers/ip4.go#L43

	L3, _ := json.Object("L3")
	L3.Set(ip4.Version, "v")
	L3.Set(ip4.SrcIP, "src")
	L3.Set(ip4.DstIP, "dst")
	L3.Set(ip4.Id, "id")
	L3.Set(ip4.IHL, "ihl")
	L3.Set(ip4.TTL, "ttl")
	L3.Set(ip4.TOS, "tos")
	L3.Set(ip4.Length, "len")
	L3.Set(ip4.FragOffset, "foff")
	L3.Set(ip4.Checksum, "xsum")

	opts, _ := L3.ArrayOfSize(len(ip4.Options), "opts")
	for i, opt := range ip4.Options {
		o, _ := opts.ObjectI(i)
		o.Set(string(opt.OptionData), "data")
		o.Set(opt.OptionType, "type")
	}

	proto, _ := L3.Object("proto")
	proto.Set(ip4.Protocol, "num")
	proto.Set(ip4.Protocol.String(), "name")
	// https://github.com/google/gopacket/blob/master/layers/ip4.go#L28-L40
	L3.SetP(strings.Split(ip4.Flags.String(), "|"), "flags")

	// hashing bytes yields `uint64`, and addition is commutatie:
	//   - so hashing the IP byte array representations and then adding then resulting `uint64`s is a commutative operation as well.
	flowID := fnv1a.HashUint64(uint64(4) + fnv1a.HashBytes64(ip4.SrcIP.To4()) + fnv1a.HashBytes64(ip4.DstIP.To4()))
	flowIDstr := strconv.FormatUint(flowID, 10)
	L3.Set(flowIDstr, "flow") // IPv4(4) (0x04)

	return json
}

func (t *JSONPcapTranslator) translateIPv6Layer(ctx context.Context, ip6 *layers.IPv6) fmt.Stringer {
	json := gabs.New()

	// https://github.com/google/gopacket/blob/master/layers/ip6.go#L28-L43

	L3, _ := json.Object("L3")
	L3.Set(ip6.Version, "v")
	L3.Set(ip6.SrcIP, "src")
	L3.Set(ip6.DstIP, "dst")
	L3.Set(ip6.Length, "len")
	L3.Set(ip6.TrafficClass, "tclass")
	L3.Set(ip6.FlowLabel, "flabel")
	L3.Set(ip6.HopLimit, "hlimit")

	proto, _ := L3.Object("proto")
	proto.Set(ip6.NextHeader, "num")
	proto.Set(ip6.NextHeader.String(), "name")

	// hashing bytes yields `uint64`, and addition is commutatie:
	//   - so hashing the IP byte array representations and then adding then resulting `uint64`s is a commutative operation as well.
	flowID := fnv1a.HashUint64(uint64(41) + fnv1a.HashBytes64(ip6.SrcIP.To16()) + fnv1a.HashBytes64(ip6.DstIP.To16()))
	flowIDstr := strconv.FormatUint(flowID, 10)
	L3.Set(flowIDstr, "flow") // IPv6(41) (0x29)

	// missing `HopByHop`: https://github.com/google/gopacket/blob/master/layers/ip6.go#L40
	return json
}

func (t *JSONPcapTranslator) translateUDPLayer(ctx context.Context, udp *layers.UDP) fmt.Stringer {
	json := gabs.New()

	// https://github.com/google/gopacket/blob/master/layers/udp.go#L17-L25

	L4, _ := json.Object("L4")

	L4.Set(udp.Checksum, "xsum")
	L4.Set(udp.Length, "len")

	L4.Set(udp.SrcPort, "src")
	if name, ok := layers.UDPPortNames[udp.SrcPort]; ok {
		L4.Set(name, "sproto")
	}

	L4.SetP(udp.DstPort, "dst")
	if name, ok := layers.UDPPortNames[udp.DstPort]; ok {
		L4.Set(name, "dproto")
	}

	// UDP(17) (0x11) | `SrcPort` and `DstPort` are `uint8`
	flowID := fnv1a.HashUint64(uint64(17) + uint64(udp.SrcPort) + uint64(udp.DstPort))
	flowIDstr := strconv.FormatUint(flowID, 10)
	L4.Set(flowIDstr, "flow")

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
	L4.Set(tcp.Checksum, "xsum")
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

	if flagsStr, ok := tcpFlagsStr[setFlags]; ok {
		flags.Set(flagsStr, "str")
	} else {
		// this scenario is slow, but it should also be exceedingly rare
		flagsStr := make([]string, 0, len(tcpFlags))
		for key := range tcpFlags {
			if isSet, _ := flagsMap.Path(key).Data().(bool); isSet {
				flagsStr = append(flagsStr, key)
			}
		}
		flags.Set(strings.Join(flagsStr, "|"), "str")
	}

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

	// TCP(6) (0x06) | `SrcPort` and `DstPort` are `uint8`
	flowID := fnv1a.HashUint64(uint64(6) + uint64(tcp.SrcPort) + uint64(tcp.DstPort))
	flowIDstr := strconv.FormatUint(flowID, 10)
	L4.Set(flowIDstr, "flow")

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

		soaJSON, _ := a.Object("SOA")
		soaJSON.Set(string(answer.SOA.MName), "mname")
		soaJSON.Set(string(answer.SOA.RName), "rname")
		soaJSON.Set(answer.SOA.Serial, "serial")
		soaJSON.Set(answer.SOA.Expire, "expire")
		soaJSON.Set(answer.SOA.Refresh, "refresh")
		soaJSON.Set(answer.SOA.Retry, "retry")

		srvJSON, _ := a.Object("SRV")
		srvJSON.SetP(string(answer.SRV.Name), "name")
		srvJSON.SetP(answer.SRV.Port, "port")
		srvJSON.SetP(answer.SRV.Weight, "weight")
		srvJSON.SetP(answer.SRV.Priority, "priority")

		/*
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
	conntrack bool,
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
	flowIDstr, _ := json.Path("meta.flow").Data().(string) // this is always available
	flowID, _ := strconv.ParseUint(flowIDstr, 10, 64)
	if l3FlowIDstr, l3OK := json.Path("L3.flow").Data().(string); l3OK {
		l3FlowID, _ := strconv.ParseUint(l3FlowIDstr, 10, 64)
		flowID = fnv1a.AddUint64(flowID, l3FlowID)
	}
	if l4FlowIDstr, l4OK := json.Path("L4.flow").Data().(string); l4OK {
		l4FlowID, _ := strconv.ParseUint(l4FlowIDstr, 10, 64)
		flowID = fnv1a.AddUint64(flowID, l4FlowID)
	} else {
		flowID = fnv1a.AddUint64(flowID, 255) // RESERVED (0xFF)
	}
	flowIDstr = strconv.FormatUint(flowID, 10)

	data["flowID"] = flowIDstr
	json.Set(flowIDstr, "flow")

	if !isTCP && !isUDP {
		operation.Set(stringFormatter.Format(jsonTranslationFlowTemplate, id, t.iface.Name, "x", flowIDstr), "id")
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
		operation.Set(stringFormatter.Format(jsonTranslationFlowTemplate, id, t.iface.Name, "udp", flowIDstr), "id")
		json.Set(stringFormatter.FormatComplex(jsonTranslationSummaryUDP, data), "message")
		return json, nil
	}

	data["L4Proto"] = "TCP"
	srcPort, _ := json.Path("L4.src").Data().(layers.TCPPort)
	data["L4Src"] = uint16(srcPort)
	dstPort, _ := json.Path("L4.dst").Data().(layers.TCPPort)
	data["L4Dst"] = uint16(dstPort)

	setFlags, _ := json.Path("L4.flags.dec").Data().(uint8)
	data["tcpFlags"] = json.Path("L4.flags.str").Data().(string)

	seq, _ := json.Path("L4.seq").Data().(uint32)
	data["tcpSeq"] = seq
	ack, _ := json.Path("L4.ack").Data().(uint32)
	data["tcpAck"] = ack

	operation.Set(stringFormatter.Format(jsonTranslationFlowTemplate, id, t.iface.Name, "tcp", flowIDstr), "id")

	message := stringFormatter.FormatComplex(jsonTranslationSummaryTCP, data)

	// `finalize` is invoked from a `worker` via a go-routine `pool`:
	//   - there are no guarantees about which packet will get `finalize`d 1st
	//   - there are no guarantees about about which packet will get the `lock` next
	// minimize locking: lock per-flow instead of across-flows.
	// Locking is done in the name of throubleshoot-ability, so some contention at the flow level should be acceptable...
	lock, traceAndSpanProvider := t.fm.lock(ctx, serial, &flowID, &setFlags, &seq, &ack)

	if conntrack {
		t.analyzeConnection(p, &flowID, &setFlags, json)
	}

	appLayer := (*p).ApplicationLayer()
	if (setFlags == tcpAck || setFlags == tcpPsh || setFlags == tcpPshAck) && appLayer != nil {
		return t.addAppLayerData(ctx, p, lock, &flowID, &setFlags, &seq, &appLayer, json, &message, traceAndSpanProvider)
	}

	if !lock.IsHTTP2() {
		// most ingress traffic is HTTP/1.1 , so:
		//   - try to get trace tracking information using h1 stream id
		streamID := http11StreamID
		if ts, ok := traceAndSpanProvider(&streamID); ok {
			t.setTraceAndSpan(json, ts)
		}
	}

	json.Set(message, "message")

	// packet is not carrying any data, unlock using TCP flags
	_, lockLatency := lock.UnlockWithTCPFlags(ctx, &setFlags)
	json.Set(lockLatency.String(), "ll")

	return json, nil
}

func (t *JSONPcapTranslator) analyzeConnection(
	_ *gopacket.Packet,
	_ *uint64, /* flowID */
	_ *uint8, /* TCP flags */
	_ *gabs.Container, /* JSON object */
) {
	// implement connection tracking
}

func (t *JSONPcapTranslator) addAppLayerData(
	ctx context.Context,
	packet *gopacket.Packet,
	lock *flowLock,
	flowID *uint64,
	tcpFlags *uint8,
	sequence *uint32,
	appLayer *gopacket.ApplicationLayer,
	json *gabs.Container,
	message *string,
	tsp TraceAndSpanProvider,
) (*gabs.Container, error) {
	appLayerData := (*appLayer).LayerContents()

	sizeOfAppLayerData := len(appLayerData)
	if sizeOfAppLayerData == 0 {
		_, lockLatency := lock.UnlockWithTCPFlags(ctx, tcpFlags)
		json.Set(lockLatency.String(), "ll")
		return json, errors.New("AppLayer is empty")
	}

	if L7, handled, isHTTP2 := t.trySetHTTP(ctx, packet, lock, flowID,
		tcpFlags, sequence, appLayerData, json, message, tsp); handled {
		// this `size` is not the same as `length`:
		//   - `size` includes everything, not only the HTTP `payload`
		L7.Set(sizeOfAppLayerData, "size")
		// HTTP/2.0 is binary so not showing it raw
		if !isHTTP2 && sizeOfAppLayerData > 512 {
			L7.Set(string(appLayerData[:512-3])+"...", "raw")
		} else if !isHTTP2 {
			L7.Set(string(appLayerData), "raw")
		}
		return json, nil
	}

	// best-effort to add some information about L7
	json.Set(stringFormatter.Format("{0} | size:{1}",
		*message, sizeOfAppLayerData), "message")

	L7, _ := json.Object("L7")
	L7.Set(sizeOfAppLayerData, "length")

	if sizeOfAppLayerData > 128 {
		L7.Set(string(appLayerData[:128-3])+"...", "sample")
	} else {
		L7.Set(string(appLayerData), "content")
	}

	_, lockLatency := lock.UnlockWithTCPFlags(ctx, tcpFlags)
	json.Set(lockLatency.String(), "ll")

	return json, nil
}

func (t *JSONPcapTranslator) trySetHTTP(
	ctx context.Context,
	packet *gopacket.Packet,
	lock *flowLock,
	flowID *uint64,
	tcpFlags *uint8,
	sequence *uint32,
	appLayerData []byte,
	json *gabs.Container,
	message *string,
	tsp TraceAndSpanProvider,
) (*gabs.Container, bool /* handled */, bool /* isHTTP2 */) {
	isHTTP11Request := http11RequestPayloadRegex.Match(appLayerData)
	isHTTP11Response := !isHTTP11Request && http11ResponsePayloadRegex.Match(appLayerData)

	isHTTP2 := !isHTTP11Request && !isHTTP11Response && http2PrefaceRegex.Match(appLayerData)
	framer := http2.NewFramer(io.Discard, bytes.NewReader(appLayerData))
	frame, frameErr := framer.ReadFrame()

	// if content is not HTTP in clear text, abort
	if !isHTTP11Request && !isHTTP11Response && !isHTTP2 && frame == nil {
		return json, false, false
	}

	// SETs are used to avoid duplicates
	streams := mapset.NewThreadUnsafeSet[uint32]()
	requestStreams := mapset.NewThreadUnsafeSet[uint32]()
	responseStreams := mapset.NewThreadUnsafeSet[uint32]()
	dataStreams := mapset.NewThreadUnsafeSet[uint32]()
	requestTS := make(map[uint32]*traceAndSpan)
	responseTS := make(map[uint32]*traceAndSpan)

	// making at least 1 big assumption:
	//   HTTP request/status line and headers fit in 1 packet
	//     which is not always the case when fragmentation occurs
	L7, _ := json.Object("HTTP")

	defer func() {
		var lockLatency *time.Duration = nil
		if requestStreams.Cardinality() > 0 ||
			responseStreams.Cardinality() > 0 {
			_, lockLatency = lock.UnlockWithTraceAndSpan(
				ctx, tcpFlags, isHTTP2, requestStreams.ToSlice(),
				responseStreams.ToSlice(), requestTS, responseTS,
			)
		} else {
			_, lockLatency = lock.UnlockWithTCPFlags(ctx, tcpFlags)
		}
		json.Set(lockLatency.String(), "ll")
	}()

	if isHTTP2 {
		L7.Set(true, "preface")
		h2cData := http2PrefaceRegex.ReplaceAll(appLayerData, nil)
		if len(h2cData) == 0 {
			L7.Set("h2c", "proto")
			L7.Set(string(appLayerData), "raw")
			return L7, true, true
		}
		framer = http2.NewFramer(io.Discard, bytes.NewReader(h2cData))
		frame, frameErr = framer.ReadFrame()
	}

	isHTTP2 = (isHTTP2 || frame != nil)

	// handle h2c traffic
	if isHTTP2 {
		L7.Set("h2c", "proto")
		streamsJSON, _ := L7.Object("streams")

		// multple h2 frames ( from multiple streams ) may be delivered by the same packet
		for frame != nil {

			isRequest := false
			isResponse := false

			frameHeader := frame.Header()

			// h2 is multiplexed, `StreamID` will allows to link HTTP conversations
			//   - see: https://datatracker.ietf.org/doc/html/rfc9113#name-stream-identifiers
			//     - Streams initiated by a client MUST use odd-numbered stream identifiers
			//     - Streams initiated by the server MUST use even-numbered stream identifiers
			//     - A stream identifier of zero (0x00) is used for connection control messages
			//     - Stream identifiers cannot be reused.
			// A stream is equal to a single HTTP conversation: request and response.
			StreamID := frameHeader.StreamID
			StreamIDstr := strconv.FormatUint(uint64(StreamID), 10)
			streams.Add(StreamID)

			ts, traced := tsp(&StreamID)

			var stream, frames *gabs.Container
			if stream = streamsJSON.S(StreamIDstr); stream == nil {
				stream, _ = streamsJSON.Object(StreamIDstr)
				_, _ = stream.Array("frames")
				stream.Set(StreamID, "id")
			} else if frames = stream.S("frames"); frames == nil {
				_, _ = stream.Array("frames")
			}

			frameJSON := gabs.New()
			stream.ArrayAppend(frameJSON, "frames")

			if m := http2RawFrameRegex.
				FindStringSubmatch(frameHeader.String()); len(m) > 0 {
				frameJSON.Set(m[1], "raw")
			}

			sizeOfFrame := frameHeader.Length /* uint32 */
			frameJSON.Set(sizeOfFrame, "length")

			// see: https://pkg.go.dev/golang.org/x/net/http2#Flags
			frameJSON.Set("0b"+strconv.FormatUint(uint64(frameHeader.Flags /* uint8 */), 2), "flags")

			var _ts *traceAndSpan = nil

			switch frame := frame.(type) {
			case *http2.PingFrame:
				frameJSON.Set("ping", "type")
				frameJSON.Set(frame.IsAck(), "ack")
				frameJSON.Set(string(frame.Data[:]), "data")

			case *http2.SettingsFrame:
				frameJSON.Set("sttings", "type")
				settings, _ := frameJSON.Object("settings")
				frame.ForeachSetting(func(s http2.Setting) error {
					// see: https://pkg.go.dev/golang.org/x/net/http2#SettingID
					settings.Set(strconv.FormatUint(uint64(s.Val), 10),
						"0x"+strconv.FormatUint(uint64(s.ID), 16))
					return nil
				})
				frameJSON.Set(frame.IsAck(), "ack")

			case *http2.HeadersFrame:
				frameJSON.Set("headers", "type")
				decoder := hpack.NewDecoder(2048, nil)
				hf, _ := decoder.DecodeFull(frame.HeaderBlockFragment())
				headers := http.Header{}
				for _, header := range hf {
					isRequest = (isRequest || (header.Name == ":method"))
					isResponse = (isResponse || (header.Name == ":status"))
					// `Add(...)` internally applies `http.CanonicalHeaderKey(...)`
					headers.Add(header.Name, header.Value)
				}
				decoder.Close()
				if _ts = t.addHTTPHeaders(frameJSON, &headers); _ts != nil {
					_ts.streamID = &StreamID
					if isRequest {
						requestTS[StreamID] = _ts
					} else if isResponse {
						responseTS[StreamID] = _ts
					}
				} else if traced && isResponse {
					responseTS[StreamID] = ts
				}

			case *http2.MetaHeadersFrame:
				frameJSON.Set("metadata", "type")
				mdJSON, _ := frameJSON.Object("metadata")
				for _, md := range frame.Fields {
					mdJSON.Set(md.Value, md.Name)
				}

			case *http2.DataFrame:
				dataStreams.Add(StreamID)
				frameJSON.Set("data", "type")
				data := frame.Data()
				sizeOfData := int64(sizeOfFrame)
				t.addHTTPBodyDetails(frameJSON, &sizeOfData, bytes.NewReader(data))
			}

			if isRequest {
				requestStreams.Add(StreamID)
				frameJSON.Set("request", "kind")
			} else if isResponse {
				responseStreams.Add(StreamID)
				frameJSON.Set("response", "kind")
			}

			// multiple streams with frames for req/res
			// might arrive within the same TCP segment
			if _ts != nil {
				t.setTraceAndSpan(frameJSON, _ts)
			} else if traced {
				t.setTraceAndSpan(frameJSON, ts)
			}

			// read next frame
			frame, frameErr = framer.ReadFrame()
		}

		if frameErr != nil && frameErr != io.EOF {
			errorJSON, _ := L7.Object("error")
			errorJSON.Set("INVALID_HTTP2_FRAME", "code")
			errorJSON.Set(frameErr.Error(), "info")
		}

		streamsJSONbytes, err := streams.MarshalJSON()
		if err == nil {
			L7.Set(string(streamsJSONbytes), "includes")
		} else {
			L7.Set(streams.ToSlice(), "includes")
		}

		sizeOfStreams := streams.Cardinality()
		if (sizeOfStreams == 1 && streams.Contains(0)) || sizeOfStreams > 10 {
			json.Set(stringFormatter.Format("{0} | {1}", *message, "h2c"), "message")
		} else {
			json.Set(stringFormatter.Format("{0} | {1} | streams:{2} | req:{3} | res:{4} | data:{5}", *message, "h2c",
				streams.ToSlice(), requestStreams.ToSlice(), responseStreams.ToSlice(), dataStreams.ToSlice()), "message")
		}

		return L7, true, true
	}

	// HTTP/1.1 is not multiplexed, so `StreamID` is always `1`
	StreamID := http11StreamID
	ts, traced := tsp(&StreamID)

	streams.Add(StreamID)

	fragmented := false // stop tracking is the default behavior
	defer func() {
		// some HTTP Servers split headers and body by flushing immediately after headers,
		// so if this packet is carrying an HTTP Response, stop trace-tracking if:
		//   - the packet contains the full HTTP Response body, or more specifically:
		//     - if the `Content-Length` header value is equal to the observed `size-of-payload`:
		//       - which means that the HTTP Response is not fragmented.
		L7.Set(fragmented, "fragmented")
	}()

	// L7 is a quasi-RAW representation of the HTTP message.
	// see: https://www.rfc-editor.org/rfc/rfc7540#section-8.1.3
	dataBytes := bytes.SplitN(appLayerData, http11BodySeparator, 2)
	// `parts` is everything before HTTP payload separator (`2*line-break`)
	//   - it includes: the HTTP line, and HTTP headers
	parts := bytes.Split(dataBytes[0], http11Separator)
	meta, _ := json.Object("L7") // `parts[0]` is the HTTP/1.1 preface
	meta.Set("HTTP", "proto")
	meta.Set(string(parts[0]), "preface")
	metaHeaders, _ := meta.ArrayOfSize(len(parts)-1, "headers")
	// HTTP headers starts at `parts[1]`
	for i, header := range parts[1:] {
		metaHeaders.SetIndex(string(header), i)
	}
	if len(dataBytes) > 1 {
		parts = bytes.Split(dataBytes[1], http11Separator)
		body, _ := meta.ArrayOfSize(len(parts), "body")
		for i, part := range parts {
			if len(part) > 128 {
				body.SetIndex(string(part[:128-3])+"...", i)
			} else {
				body.SetIndex(string(part), i)
			}
		}
	}

	httpDataReader := bufio.NewReaderSize(bytes.NewReader(appLayerData), len(appLayerData))

	// attempt to parse HTTP/1.1 request
	if isHTTP11Request {
		requestStreams.Add(StreamID)
		request, err := http.ReadRequest(httpDataReader)

		if err != nil && err != io.EOF {
			errorJSON, _ := L7.Object("error")
			errorJSON.Set("INVALID_HTTP11_RESPONSE", "code")
			errorJSON.Set(err.Error(), "info")
			json.Set(stringFormatter.Format("{0} | {1}: {2}",
				*message, "INVALID_HTTP11_REQUEST", err.Error()), "message")
			return L7, true, false
		}

		L7.Set("request", "kind")
		url := request.URL.String()
		L7.Set(url, "url")
		L7.Set(request.Proto, "proto")
		L7.Set(request.Method, "method")
		if _ts := t.addHTTPHeaders(L7, &request.Header); _ts != nil {
			_ts.streamID = &StreamID
			requestTS[StreamID] = _ts
			// include trace and span id for traceability
			t.setTraceAndSpan(json, _ts)
			t.recordHTTP11Request(packet, flowID, sequence, _ts, &request.Method, &request.Host, &url)
		}
		sizeOfBody := t.addHTTPBodyDetails(L7, &request.ContentLength, request.Body)
		if sizeOfBody > 0 {
			dataStreams.Add(StreamID)
		}
		if cl, clErr := strconv.ParseUint(request.Header.Get(httpContentLengthHeader), 10, 64); clErr == nil {
			fragmented = cl > sizeOfBody
		}
		json.Set(stringFormatter.Format("{0} | {1} {2} {3}", *message, request.Proto, request.Method, url), "message")
		return L7, true, false
	}

	// attempt to parse HTTP/1.1 response
	if isHTTP11Response {
		responseStreams.Add(StreamID)
		// Go's `http` implementation may miss the `Transfer-Encoding` header
		//   - see: https://github.com/golang/go/issues/27061
		response, err := http.ReadResponse(httpDataReader, nil)

		if err != nil && err != io.EOF {
			errorJSON, _ := L7.Object("error")
			errorJSON.Set("INVALID_HTTP11_RESPONSE", "code")
			errorJSON.Set(err.Error(), "info")
			json.Set(stringFormatter.Format("{0} | {1}: {2}",
				*message, "INVALID_HTTP11_RESPONSE", err.Error()), "message")
			return L7, true, false
		}

		L7.Set("response", "kind")
		L7.Set(response.Proto, "proto")
		L7.Set(response.StatusCode, "code")
		L7.Set(response.Status, "status")
		if _ts := t.addHTTPHeaders(L7, &response.Header); _ts != nil {
			_ts.streamID = &StreamID
			responseTS[StreamID] = _ts
			// include trace and span id for traceability
			t.setTraceAndSpan(json, _ts)
			if linkErr := t.linkHTTP11ResponseToRequest(packet, flowID, L7, _ts); linkErr != nil {
				io.WriteString(os.Stderr, linkErr.Error()+"\n")
			}
		} else if traced {
			responseTS[StreamID] = ts
			t.setTraceAndSpan(json, ts)
			t.linkHTTP11ResponseToRequest(packet, flowID, L7, ts)
		}
		sizeOfBody := t.addHTTPBodyDetails(L7, &response.ContentLength, response.Body)
		if sizeOfBody > 0 {
			dataStreams.Add(StreamID)
		}
		if cl, clErr := strconv.ParseUint(response.Header.Get(httpContentLengthHeader), 10, 64); clErr == nil {
			// if content-length is greater than the size of body:
			//   - this HTTP message is fragmented and so there's more to come
			fragmented = cl > sizeOfBody
		}
		json.Set(stringFormatter.Format("{0} | {1} {2}",
			*message, response.Proto, response.Status), "message")
		return L7, true, false
	}

	return json, true, false
}

func (t *JSONPcapTranslator) addHTTPBodyDetails(L7 *gabs.Container, contentLength *int64, body io.Reader) uint64 {
	bodyBytes, err := io.ReadAll(body)
	if err != nil {
		return uint64(0)
	}

	bodyJSON, _ := L7.Object("body")

	sizeOfBody := uint64(len(bodyBytes))
	bodyLengthJSON, _ := bodyJSON.ArrayOfSize(2, "length")
	bodyLengthJSON.SetIndex(strconv.FormatUint(sizeOfBody, 10), 0)
	bodyLengthJSON.SetIndex(strconv.FormatInt(*contentLength, 10), 1)

	if sizeOfBody > 512 {
		bodyJSON.Set(string(bodyBytes[:512-3])+"...", "sample")
	} else if sizeOfBody > 0 {
		bodyJSON.Set(string(bodyBytes), "data")
	}

	return sizeOfBody
}

func (t *JSONPcapTranslator) recordHTTP11Request(
	packet *gopacket.Packet,
	_ *uint64, /* flowID */
	_ *uint32, /* TCP sequence */
	ts *traceAndSpan,
	method, host, url *string,
) {
	fullURL := stringFormatter.Format("{0}{1}", *host, *url)
	_httpRequest := &httpRequest{
		timestamp: &(*packet).Metadata().Timestamp,
		method:    method,
		url:       &fullURL,
	}
	t.traceToHttpRequestMap.Set(*ts.traceID, _httpRequest)
}

func (t *JSONPcapTranslator) linkHTTP11ResponseToRequest(
	packet *gopacket.Packet,
	_ *uint64, /* flowID */
	response *gabs.Container,
	ts *traceAndSpan,
) error {
	jsonTranslatorRequest, ok := t.traceToHttpRequestMap.Get(*ts.traceID)
	if !ok {
		return errors.New(stringFormatter.Format("no request found for trace-id: {0}", *ts.traceID))
	}

	translatorRequest := *jsonTranslatorRequest
	// hydrate response with information from request
	request, _ := response.Object("request")
	request.Set(*translatorRequest.method, "method")
	request.Set(*translatorRequest.url, "url")
	requestTimestamp := *translatorRequest.timestamp
	responseTimestamp := (*packet).Metadata().Timestamp
	latency := responseTimestamp.Sub(requestTimestamp)
	request.Set(requestTimestamp.Format(time.RFC3339Nano), "timestamp")
	request.Set(latency.Milliseconds(), "latency")

	// intentionally not removing from `traceToHttpRequestMap`:
	//   - it will be done by `untrackConnection` on `RST` or `FIN+ACK`
	//   - allows to link multiple `traceID`s with the same flow
	return nil
}

func (t *JSONPcapTranslator) addHTTPHeaders(L7 *gabs.Container, headers *http.Header) *traceAndSpan {
	jsonHeaders, _ := L7.Object("headers")
	var traceAndSpan *traceAndSpan = nil
	for key, value := range *headers {
		jsonHeaders.Set(value, key)
		for headerStr, headerRgx := range traceAndSpanRegex {
			if strings.EqualFold(key, headerStr) {
				traceAndSpan = t.getTraceAndSpan(headerRgx, &value[0])
			}
		}
	}
	return traceAndSpan
}

func (t *JSONPcapTranslator) getTraceAndSpan(
	headerRgx *regexp.Regexp,
	rawTraceAndSpan *string,
) *traceAndSpan {
	if ts := headerRgx.FindStringSubmatch(*rawTraceAndSpan); ts != nil {
		return &traceAndSpan{traceID: &ts[1], spanID: &ts[2]}
	}
	return nil
}

func (t *JSONPcapTranslator) setTraceAndSpan(json *gabs.Container, ts *traceAndSpan) bool {
	if ts == nil {
		json.Set(false, "logging.googleapis.com/trace_sampled")
		return false
	}

	json.Set(cloudTracePrefix+*ts.traceID, "logging.googleapis.com/trace")
	json.Set(*ts.spanID, "logging.googleapis.com/spanId")
	json.Set(true, "logging.googleapis.com/trace_sampled")

	return true
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

func newJSONPcapTranslator(ctx context.Context, debug bool, iface *PcapIface) *JSONPcapTranslator {
	flowToStreamToSequenceMap := haxmap.New[uint64, FTSM]()
	traceToHttpRequestMap := haxmap.New[string, *httpRequest]()
	flowMutex := newFlowMutex(ctx, debug, flowToStreamToSequenceMap, traceToHttpRequestMap)

	return &JSONPcapTranslator{
		fm:                        flowMutex,
		iface:                     iface,
		traceToHttpRequestMap:     traceToHttpRequestMap,
		flowToStreamToSequenceMap: flowToStreamToSequenceMap,
	}
}
