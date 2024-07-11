package transformer

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"hash/fnv"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/Jeffail/gabs/v2"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/pkg/errors"
	"github.com/wissance/stringFormatter"

	csmap "github.com/mhmtszr/concurrent-swiss-map"
)

type (
	JSONTranslatorRequest struct {
		timestamp   *time.Time
		url, method *string
	}
	JSONPcapTranslator struct {
		iface    *PcapIface
		requests csmap.CsMap[string, *JSONTranslatorRequest]
	}
)

const (
	jsonTranslationSummary          = "#:{serial} | @:{ifaceIndex}/{ifaceName} | "
	jsonTranslationSummaryWithoutL4 = jsonTranslationSummary + "{L3Src} > {L3Dst}"
	jsonTranslationSummaryUDP       = jsonTranslationSummary + "{L4Proto} | {srcProto}/{L3Src}:{L4Src} > {dstProto}/{L3Dst}:{L4Dst}"
	jsonTranslationSummaryTCP       = jsonTranslationSummaryUDP + " | [{tcpFlags}] | seq:{tcpSeq} | ack:{tcpAck}"
)

func (t *JSONPcapTranslator) translate(packet *gopacket.Packet) error {
	return fmt.Errorf("not implemented")
}

// return pointer to `struct` `gabs.Container`
func (t *JSONPcapTranslator) next(ctx context.Context, packet *gopacket.Packet, serial *uint64) fmt.Stringer {
	json := gabs.New()

	id := ctx.Value(ContextID)
	logName := ctx.Value(ContextLogName)

	operation, _ := json.Object("logging.googleapis.com/operation")
	operation.Set(id, "id")
	operation.Set(logName, "producer")
	if *serial == 1 {
		operation.Set(true, "first")
	}

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

	labels, _ := json.Object("logging.googleapis.com/labels")
	labels.Set(id, "pcap_id")
	labels.Set(t.iface.Name, "pcap_iface")

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

	opts, _ := json.ArrayOfSize(len(ip.Options), "opts")
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
	L3.Set(ip.NextHeader.String(), "next_header")
	L3.Set(ip.HopLimit, "hop_limit")

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

	flags, _ := L4.Object("flags")
	flags.Set(tcp.SYN, "SYN")
	flags.Set(tcp.ACK, "ACK")
	flags.Set(tcp.PSH, "PSH")
	flags.Set(tcp.FIN, "FIN")
	flags.Set(tcp.RST, "RST")
	flags.Set(tcp.URG, "URG")
	flags.Set(tcp.ECE, "ECE")
	flags.Set(tcp.CWR, "CWR")
	flags.Set(tcp.NS, "NS")

	opts, _ := json.ArrayOfSize(len(tcp.Options), "opts")
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

// for JSON translator, this mmethod generates the summary line at {`message`: $summary}
func (t *JSONPcapTranslator) finalize(ctx context.Context, p *gopacket.Packet, packet fmt.Stringer) (fmt.Stringer, error) {
	json := t.asTranslation(packet)

	data := make(map[string]any, 15)

	data["ifaceIndex"] = t.iface.Index
	data["ifaceName"] = t.iface.Name

	serial, _ := json.Path("pcap.num").Data().(uint64)
	data["serial"] = serial

	l3Src, _ := json.Path("L3.src").Data().(net.IP)
	data["L3Src"] = l3Src
	l3Dst, _ := json.Path("L3.dst").Data().(net.IP)
	data["L3Dst"] = l3Dst

	proto := json.Path("L3.proto.num").Data().(layers.IPProtocol)
	isTCP := proto == layers.IPProtocolTCP
	isUDP := proto == layers.IPProtocolUDP

	if !isTCP && !isUDP {
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
		data["L4Src"] = int(srcPort)
		dstPort, _ := json.Path("L4.dst").Data().(layers.UDPPort)
		data["L4Dst"] = int(dstPort)

		json.Set(stringFormatter.FormatComplex(jsonTranslationSummaryUDP, data), "message")
		return json, nil
	}

	data["L4Proto"] = "TCP"

	srcPort, _ := json.Path("L4.src").Data().(layers.TCPPort)
	data["L4Src"] = int(srcPort)
	dstPort, _ := json.Path("L4.dst").Data().(layers.TCPPort)
	data["L4Dst"] = int(dstPort)

	flags := make([]string, 0, len(tcpFlagNames))
	for _, flagName := range tcpFlagNames {
		if isSet, _ := json.Path(`L4.flags.` + flagName).Data().(bool); isSet {
			flags = append(flags, flagName)
		}
	}

	data["tcpFlags"] = strings.Join(flags, "|")

	seq, _ := json.Path("L4.seq").Data().(uint32)
	data["tcpSeq"] = seq
	ack, _ := json.Path("L4.ack").Data().(uint32)
	data["tcpAck"] = ack

	message := stringFormatter.FormatComplex(jsonTranslationSummaryTCP, data)

	// simple/naive HTTP decoding
	appLayer := (*p).ApplicationLayer()
	if appLayer == nil {
		json.Set(message, "message")
		return json, nil
	}

	t.setHTTP11(p, &appLayer, json, &message)

	return json, nil
}

func (t *JSONPcapTranslator) setHTTP11(
	packet *gopacket.Packet,
	appLayer *gopacket.ApplicationLayer,
	json *gabs.Container,
	message *string,
) {
	appLayerData := (*appLayer).LayerContents()

	isHTTP11Request := http11RequestPayloadRegex.Match(appLayerData)
	isHTTP11Response := !isHTTP11Request && http11ResponsePayloadRegex.Match(appLayerData)

	// if content is not HTTP in clear text, abort
	if !isHTTP11Request && !isHTTP11Response {
		json.Set(*message, "message")
		return
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
				// include trace and span id for traceability
				t.setTraceAndSpan(json, &traceAndSpan[0], &traceAndSpan[1])
				t.recordHTTP11Request(packet, &traceAndSpan[0], &request.Method, &request.Host, &url)
			}
			json.Set(stringFormatter.Format("{0} | {1} {2} {3}", *message, request.Proto, request.Method, url), "message")
			return
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
				if err := t.linkHTTP11ResponseToRequest(packet, L7, &traceAndSpan[0]); err != nil {
					io.WriteString(os.Stderr, err.Error())
				}
			}
			json.Set(stringFormatter.Format("{0} | {1} {2}", *message, response.Proto, response.Status), "message")
			return
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
			t.recordHTTP11Request(packet, &traceAndSpan[0], &requestParts[1], &host, &requestParts[2])
		}
		return
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
		if err := t.linkHTTP11ResponseToRequest(packet, L7, &traceAndSpan[0]); err != nil {
			io.WriteString(os.Stderr, err.Error())
		}
	}
}

func (t *JSONPcapTranslator) recordHTTP11Request(packet *gopacket.Packet, traceID, method, host, url *string) {
	fullURL := stringFormatter.Format("{0}{1}", *host, *url)
	jsonTranslatorRequest := &JSONTranslatorRequest{
		timestamp: &(*packet).Metadata().Timestamp,
		method:    method,
		url:       &fullURL,
	}
	// if a response is never seen for this trace id, it will cause a memory leak
	t.requests.SetIfAbsent(*traceID, jsonTranslatorRequest)
}

func (t *JSONPcapTranslator) linkHTTP11ResponseToRequest(packet *gopacket.Packet, response *gabs.Container, traceID *string) error {
	jsonTranslatorRequest, ok := t.requests.Load(*traceID)
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

	if !t.requests.Delete(*traceID) {
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
	requests := csmap.Create[string, *JSONTranslatorRequest](
		// set the number of map shards. the default value is 32.
		csmap.WithShardCount[string, *JSONTranslatorRequest](32),

		// if don't set custom hasher, use the built-in maphash.
		csmap.WithCustomHasher[string, *JSONTranslatorRequest](func(key string) uint64 {
			hash := fnv.New64a()
			hash.Write([]byte(key))
			return hash.Sum64()
		}),

		// set the total capacity, every shard map has total capacity/shard count capacity. the default value is 0.
		csmap.WithSize[string, *JSONTranslatorRequest](1000),
	)
	return &JSONPcapTranslator{iface: iface, requests: *requests}
}
