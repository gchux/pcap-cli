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
	"sync"
	"sync/atomic"
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
	"github.com/zhangyunhao116/skipmap"
)

type (
	TracedFlow struct {
		ts        *traceAndSpan
		unblocker *time.Timer
		isActive  *atomic.Bool
	}
	STTFM  = *skipmap.Uint32Map[*TracedFlow] // SequenceToTracedFlowMap
	FTSM   = *haxmap.Map[uint32, STTFM]      // FlowToStreamMap
	FTSTSM = *haxmap.Map[uint64, FTSM]       // FlowToStreamToSequenceMap

	TracedFlowProvider   = func(*uint32) (*TracedFlow, bool)
	TraceAndSpanProvider = func(*uint32) (*traceAndSpan, bool)

	JSONPcapTranslator struct {
		fm               *flowMutex
		iface            *PcapIface
		halfOpenFlows    mapset.Set[uint64]
		establishedFlows mapset.Set[uint64]
		halfClosedFlows  mapset.Set[uint64]
		flowToTimestamp  *haxmap.Map[uint64, *time.Time]

		traceToTraceTimer     *haxmap.Map[string, *time.Timer]
		traceToHttpRequestMap *haxmap.Map[string, *httpRequest]

		flowToStreamToSequenceMap FTSTSM
	}

	UnlockWithTraceAndSpan = func(
		[]uint32, []uint32,
		map[uint32]*traceAndSpan,
		map[uint32]*traceAndSpan,
	) *int64
	UnlockWithTCPFlags = func(*uint8 /* TCP flags */) bool
	NextStreamID       = func() uint32

	flowMutex struct {
		MutexMap                  *haxmap.Map[uint64, *flowLockCarrier]
		traceToHttpRequestMap     *haxmap.Map[string, *httpRequest]
		flowToStreamToSequenceMap FTSTSM
	}

	flowLock struct {
		Unlock                 func() bool
		UnlockAndRelease       func() bool
		UnlockWithTCPFlags     UnlockWithTCPFlags
		UnlockWithTraceAndSpan UnlockWithTraceAndSpan
	}

	flowLockCarrier struct {
		mu             *sync.Mutex
		wg             *sync.WaitGroup
		rr             chan *TracedFlow
		released       *atomic.Bool
		createdAt      *time.Time
		lastLockedAt   *time.Time
		lastUnlockedAt *time.Time
		activeRequests *atomic.Int64
	}
)

const (
	jsonTranslationSummary          = "#:{serial} | @:{ifaceIndex}/{ifaceName} | flow:{flowID} | "
	jsonTranslationSummaryWithoutL4 = jsonTranslationSummary + "{L3Src} > {L3Dst}"
	jsonTranslationSummaryUDP       = jsonTranslationSummary + "{L4Proto} | {srcProto}/{L3Src}:{L4Src} > {dstProto}/{L3Dst}:{L4Dst}"
	jsonTranslationSummaryTCP       = jsonTranslationSummaryUDP + " | [{tcpFlags}] | seq/ack:{tcpSeq}/{tcpAck}"
	jsonTranslationFlowTemplate     = "{0}/iface/{1}/flow/{2}:{3}"

	carrierDeadline  = 10 * time.Second
	trackingDeadline = 300 * time.Second
)

// [ToDo]: move `FlowMutex` into its own package/file
func newFlowMutex(
	ctx context.Context,
	flowToStreamToSequenceMap FTSTSM,
	traceToHttpRequestMap *haxmap.Map[string, *httpRequest],
) *flowMutex {
	fm := &flowMutex{
		MutexMap:                  haxmap.New[uint64, *flowLockCarrier](),
		flowToStreamToSequenceMap: flowToStreamToSequenceMap,
		traceToHttpRequestMap:     traceToHttpRequestMap,
	}
	// reap orphaned `flowLockCarrier`s
	go fm.startReaper(ctx)
	return fm
}

func (fm *flowMutex) startReaper(ctx context.Context) {
	// reaping is necessary as packets translations order is not guaranteed:
	// so if all `FIN+ACK`/`RST+*` are seen before other non-termination combinations within the same flow:
	//   - a new carrier will be created to hold its flow lock, and this carrier will not be organically reaped.
	// additionally: for connection pooling, long running not-used connections should be dropped to reclaim memory.
	ticker := time.NewTicker(carrierDeadline)

	for {
		select {
		case <-ctx.Done():
			ticker.Stop()
			return
		case <-ticker.C:
			fm.MutexMap.ForEach(
				func(flowID uint64, carrier *flowLockCarrier) bool {
					if carrier == nil ||
						carrier.lastUnlockedAt == nil ||
						!carrier.mu.TryLock() {
						return true
					}
					defer carrier.mu.Unlock()
					lastUnlocked := time.Since(*carrier.lastUnlockedAt)
					if lastUnlocked >= carrierDeadline {
						fm.MutexMap.Del(flowID)
						fm.untrackConnection(&flowID)
						io.WriteString(os.Stderr,
							fmt.Sprintf("reaped flow '%d' after %v\n", flowID, lastUnlocked))
					}
					return true
				})
		}
	}
}

func (fm *flowMutex) getTracedFlow(
	flowID *uint64, sequence *uint32,
) (TracedFlowProvider, bool) {
	streamToSequenceMap, ok := fm.flowToStreamToSequenceMap.Get(*flowID)

	// no HTTP/1.1 request with a `traceID` has been seen for this `flowID`
	if !ok { // it is also possible that packet for HTTP request for this `flowID`
		return func(_ *uint32) (*TracedFlow, bool) { return nil, false }, false
	}

	return func(stream *uint32) (*TracedFlow, bool) {
		// an HTTP/1.1 request with a `traceID` has already been seen for this `flowID`
		var tracedFlow, lastTracedFlow *TracedFlow = nil, nil
		if sttsm, ok := streamToSequenceMap.Get(*stream); ok {
			sttsm.Range(func(s uint32, tf *TracedFlow) bool {
				// Loop over the map keys (ascending sequence numbers) until one greater than `sequence` is found.
				// HTTP/1.1 is not multiplexed, so a new request using the same TCP connection ( i/e: pooling )
				// should be observed (alongside its `traceID`) with a higher sequence number than the previous one;
				// when the key (a sequence number) is greater than the current one, stop looping;
				// the previously analyzed `key` (sequence number) must be pointing to the correct `traceID`.
				// TL;DR: `traceID`s exist within a specific TCP sequence range, which configures a boundary.
				if *sequence > s {
					tracedFlow = tf
				}
				lastTracedFlow = tf
				return true
			})

			// TCP sequence number is `uint32` so it is possible
			// for for it to be rolled over if it gets too big.
			// In such case `sequence` was not greater than any `key` in the map,
			// so the last visited `key` might be pointing to the correct `traceID`
			if tracedFlow == nil {
				tracedFlow = lastTracedFlow
			}
			return tracedFlow, true
		}
		return nil, false
	}, true
}

func (fm *flowMutex) trackConnection(
	lock *flowLockCarrier,
	flowID *uint64,
	tcpFlags *uint8,
	sequence *uint32,
	ts *traceAndSpan,
) (*TracedFlow, bool) {
	if ts == nil {
		return nil, false
	}
	var isActive atomic.Bool

	tf := &TracedFlow{
		ts:       ts,
		isActive: &isActive,
	}
	isActive.Store(true)

	tf.unblocker = time.AfterFunc(trackingDeadline, func() {
		// unlock orphaned trace-tracked streams: allow termination events to continue
		if !isActive.CompareAndSwap(true, false) {
			return
		}
		lock.mu.Lock()
		defer lock.mu.Unlock()
		lock.activeRequests.Add(-1)
		lock.wg.Done()
		io.WriteString(os.Stderr, fmt.Sprintf("unblocked flow: %d\n", *flowID))
	})

	sequenceToTraceAndSpanMapProvider := func(streamToSequenceMap FTSM) STTFM {
		sequenceToTraceAndSpanMap := skipmap.NewUint32[*TracedFlow]()
		sequenceToTraceAndSpanMap.Store(*sequence, tf)
		streamToSequenceMap.Set(*ts.streamID, sequenceToTraceAndSpanMap)
		return sequenceToTraceAndSpanMap
	}

	streamToSequenceMap, _ := fm.flowToStreamToSequenceMap.
		GetOrCompute(*flowID, func() FTSM {
			streamToSequenceMap := haxmap.New[uint32, STTFM]()
			sequenceToTraceAndSpanMapProvider(streamToSequenceMap)
			return streamToSequenceMap
		})

	_, _ = streamToSequenceMap.GetOrCompute(*ts.streamID, func() STTFM {
		return sequenceToTraceAndSpanMapProvider(streamToSequenceMap)
	})

	return tf, true
}

func (fm *flowMutex) untrackConnection(flowID *uint64) {
	if ftsm, ok := fm.flowToStreamToSequenceMap.Get(*flowID); ok {
		streams := make([]uint32, ftsm.Len())
		streamIndex := 0
		ftsm.ForEach(func(stream uint32, sttsm STTFM) bool {
			streams[streamIndex] = stream
			sequences := make([]uint32, sttsm.Len())
			sequenceIndex := 0
			sttsm.Range(func(sequence uint32, tf *TracedFlow) bool {
				sequences[sequenceIndex] = sequence
				// remove orphaned `traceID`s:
				fm.traceToHttpRequestMap.Del(*tf.ts.traceID)
				sequenceIndex += 1
				return true
			})
			streamIndex += 1
			for i := sequenceIndex - 1; i >= 0; i-- {
				sttsm.Delete(sequences[i])
			}
			return true
		})
		for i := streamIndex - 1; i >= 0; i-- {
			ftsm.Del(streams[i])
		}
		fm.flowToStreamToSequenceMap.Del(*flowID)
	}
}

func (fm *flowMutex) isConnectionTermination(tcpFlags *uint8) bool {
	return *tcpFlags == tcpFinAck || *tcpFlags == tcpRstAck || *tcpFlags == tcpRst
}

func (fm *flowMutex) newFlowLockCarrier() *flowLockCarrier {
	var activeRequests atomic.Int64
	var released atomic.Bool

	activeRequests.Store(0)
	released.Store(false)
	createdAt := time.Now()

	return &flowLockCarrier{
		mu:             new(sync.Mutex),
		wg:             new(sync.WaitGroup),
		rr:             make(chan *TracedFlow, 1),
		released:       &released,
		createdAt:      &createdAt,
		activeRequests: &activeRequests,
	}
}

func (fm *flowMutex) Lock(
	ctx context.Context,
	flowID *uint64,
	tcpFlags *uint8,
	sequence, ack *uint32,
) (
	*flowLock,
	TraceAndSpanProvider,
) {
	carrier, _ := fm.MutexMap.
		GetOrCompute(*flowID,
			func() *flowLockCarrier {
				return fm.newFlowLockCarrier()
			})

	mu := carrier.mu
	wg := carrier.wg

	// changing the order os `Wait` and `Lock` causes a deadlock
	if fm.isConnectionTermination(tcpFlags) {
		// Connection termination events must wait
		// for the flow to stop being trace-tracked.
		// If this flow is not trace-tracked `Wait()` won't block.
		wg.Wait()
	}
	// it is possible that all packets for this flow arrive to `Lock` at almost the same time:
	//   - which means that termination could delete the reference to `FlowLock` from `MutexMap` while non terminating ones are waiting for the lock
	mu.Lock()

	lastLockedAt := time.Now()
	carrier.lastLockedAt = &lastLockedAt

	tracedFlowProvider, _ := fm.getTracedFlow(flowID, sequence)

	_unlock := func() {
		defer func(mu *sync.Mutex) {
			if err := recover(); err != nil {
				io.WriteString(os.Stderr,
					fmt.Sprintf("error at flow[%d]: %+v | %+v\n", *flowID, err, mu))
			}
		}(mu)
		defer mu.Unlock()
		lastUnlockedAt := time.Now()
		carrier.lastLockedAt = &lastUnlockedAt
	}

	UnlockAndReleaseFN := func() bool {
		defer _unlock()
		// many translations within the same flow may be waiting to acquire the lock;
		// if multiple translations try to release, i/e: 2*`FIN+ACK`,
		// then both will release the lock, but just 1 must yield connection untracking.
		if carrier.activeRequests.Load() == 0 &&
			carrier.released.CompareAndSwap(false, true) {
			fm.MutexMap.Del(*flowID)
			// termination packets will clean the info available for each flow
			time.AfterFunc(10*time.Second, func() {
				fm.untrackConnection(flowID)
			})
		}
		return false
	}

	UnlockWithTCPFlagsFN := func(tcpFlags *uint8) bool {
		if fm.isConnectionTermination(tcpFlags) {
			return UnlockAndReleaseFN()
		}
		_unlock()
		return false
	}

	UnlockFn := func() bool {
		return UnlockWithTCPFlagsFN(tcpFlags)
	}

	// since all TCP data is known:
	//   - it is possible to return a `traceID`
	//   - since this is guarded by a lock, it is thread-safe
	// much richer analysis is also possible

	// these are the only methods for consumers to interact with the lock
	lock := &flowLock{
		Unlock:             UnlockFn,
		UnlockAndRelease:   UnlockAndReleaseFN,
		UnlockWithTCPFlags: UnlockWithTCPFlagsFN,
	}

	if *tcpFlags == tcpPshAck {
		// provide trace tracking only for TCP `PSH+ACK`.
		// For HTTP/2 multiple streams are delivered over the same TCP connection, so:
		//   - it is possible to observe mulriple requests and responses in the same TCP segment,
		//   - `unlock` must handle the scenario where the same TCP segment contains both requests and responses.
		// It is possible to receive requests/responses without `traceID`, so:
		//   - both must be accounted to accurately calculate the total number of `activeRequests`:
		//     - this is regardless of `traceID` being available; otherwise, termination packets are blocked:
		//       - this will not trigger a deadlock as only the termination is being delayed,
		//       - the `unblocker`s will eventually allow termination packets to make progress.
		// The following flow unlocking mechanism tries to:
		//   - prevent trace tracking information removal by connection termination packets
		//   - store trace tracking information for HTTP requests: that will be used to link to HTTP responses
		lock.UnlockWithTraceAndSpan = func(
			requestStreams []uint32,
			responseStreams []uint32,
			requestTS map[uint32]*traceAndSpan,
			responseTS map[uint32]*traceAndSpan,
		) *int64 {
			defer UnlockWithTCPFlagsFN(tcpFlags)

			sizeOfRequestStreams := len(requestStreams)
			sizeOfRequestTraceAndSpans := len(requestTS)
			sizeOfResponseStreams := len(responseStreams)
			sizeOfResponseTraceAndSpans := len(responseTS)

			activeRequests := carrier.activeRequests.Load()

			// handle flow `unlock` for requests
			if sizeOfRequestTraceAndSpans > 0 || sizeOfRequestStreams > 0 {
				for _, stream := range requestStreams {
					activeRequests = carrier.activeRequests.Add(1)
					if ts, ok := requestTS[stream]; ok {
						if tf, ok := fm.trackConnection(carrier, flowID, tcpFlags, sequence, ts); ok {
							if activeRequests > 0 {
								// if HTTP more responses are seen before the currently observed requests:
								//   - do block `FIN+ACK` from making progress;
								// another alternative would be to allow the `unblocker` to call `Done()` on `wg`
								wg.Add(1)
							} else if tf.isActive.CompareAndSwap(true, false) {
								// de-activate the `unblocker` for this `TracedFlow`
								tf.unblocker.Stop()
							}
						}
					}
				}
			}

			// handle flow `unlock` for responses
			if sizeOfResponseTraceAndSpans > 0 || sizeOfResponseStreams > 0 {
				for _, stream := range responseStreams {
					activeRequests = carrier.activeRequests.Add(-1)
					if ts, ok := responseTS[stream]; ok {
						if tf, ok := tracedFlowProvider(ts.streamID); ok {
							if *tf.ts.traceID == *ts.traceID &&
								tf.isActive.CompareAndSwap(true, false) {
								tf.unblocker.Stop()
								wg.Done()
							}
						}
					}
				}
			}

			return &activeRequests
		}
	} else {
		activeRequests := carrier.activeRequests.Load()
		// do not provide trace tracking for non TCP `PSH+ACK`
		lock.UnlockWithTraceAndSpan = func(
			[]uint32, []uint32,
			map[uint32]*traceAndSpan,
			map[uint32]*traceAndSpan,
		) *int64 {
			// fallback to unlock by TCP flags
			UnlockWithTCPFlagsFN(tcpFlags)
			return &activeRequests
		}
	}

	return lock, func(streamID *uint32) (*traceAndSpan, bool) {
		if tf, ok := tracedFlowProvider(streamID); ok {
			return tf.ts, true
		}
		return nil, false
	}
}

func (t *JSONPcapTranslator) translate(_ *gopacket.Packet) error {
	return fmt.Errorf("not implemented")
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
	pcap.Set(*serial, "num")

	metadata := (*packet).Metadata()
	info := metadata.CaptureInfo

	meta, _ := json.Object("meta")
	meta.Set(metadata.Truncated, "trunc")
	meta.Set(info.Length, "len")
	meta.Set(info.CaptureLength, "cap_len")
	meta.Set(flowIDstr, "flow")

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
	flowID := fnv1a.HashUint64(uint64(4) + fnv1a.HashBytes64(ip.SrcIP.To4()) + fnv1a.HashBytes64(ip.DstIP.To4()))
	flowIDstr := strconv.FormatUint(flowID, 10)
	L3.Set(flowIDstr, "flow") // IPv4(4) (0x04)

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
	flowID := fnv1a.HashUint64(uint64(41) + fnv1a.HashBytes64(ip.SrcIP.To16()) + fnv1a.HashBytes64(ip.DstIP.To16()))
	flowIDstr := strconv.FormatUint(flowID, 10)
	L3.Set(flowIDstr, "flow") // IPv6(41) (0x29)

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

	// `finalize` is invoked from a `worker` via a go-routine `pool`:
	//   - there are no guarantees about which packet will get `finalize`d 1st
	//   - there are no guarantees about about which packet will get the `lock` next
	// minimize locking: lock per-flow instead of across-flows.
	// Locking is done in the name of throubleshoot-ability, so some contention at the flow level should be acceptable...
	lock, traceAndSpanProvider := t.fm.Lock(ctx, &flowID, &setFlags, &seq, &ack)

	if conntrack {
		t.analyzeConnection(p, &flowID, &setFlags, json)
	}

	message := stringFormatter.FormatComplex(jsonTranslationSummaryTCP, data)

	appLayer := (*p).ApplicationLayer()
	if setFlags == tcpPshAck && appLayer != nil {
		return t.addAppLayerData(ctx, lock, p, &setFlags, &appLayer, &flowID, &seq, json, &message, traceAndSpanProvider)
	}

	// packet is not carrying any data, unlock using TCP flags
	defer lock.UnlockWithTCPFlags(&setFlags)

	json.Set(message, "message")

	return json, nil
}

func (t *JSONPcapTranslator) analyzeConnection(
	packet *gopacket.Packet,
	flowID *uint64,
	flags *uint8,
	json *gabs.Container,
) {
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
	if ts, ok := t.flowToTimestamp.Get(fid); ok {
		json.Set(timestamp.Sub(*ts).Milliseconds(), "latency")
		t.flowToTimestamp.Set(fid, &timestamp)
	} else {
		t.flowToTimestamp.Set(fid, &timestamp)
	}

	if shouldRemoveTracking {
		t.flowToTimestamp.Del(fid)
	}
}

func (t *JSONPcapTranslator) addAppLayerData(
	ctx context.Context,
	lock *flowLock,
	packet *gopacket.Packet,
	tcpFlags *uint8,
	appLayer *gopacket.ApplicationLayer,
	flowID *uint64,
	sequence *uint32,
	json *gabs.Container,
	message *string,
	tsp TraceAndSpanProvider,
) (*gabs.Container, error) {
	appLayerData := (*appLayer).LayerContents()

	sizeOfAppLayerData := len(appLayerData)
	if sizeOfAppLayerData == 0 {
		defer lock.UnlockWithTCPFlags(tcpFlags)
		return json, errors.New("AppLayer is empty")
	}

	if L7, ok := t.trySetHTTP(ctx, lock, packet, tcpFlags,
		appLayerData, flowID, sequence, json, message, tsp); ok {
		// this `size` is not the same as `length`:
		//   - `size` includes everything, not only the HTTP `payload`
		L7.Set(sizeOfAppLayerData, "size")
		// `trySetHTTP11()` unlocks if data is HTTP
		return json, nil
	}

	defer lock.UnlockWithTCPFlags(tcpFlags)

	// best-effort to add some information about L7
	json.Set(stringFormatter.Format("{0} | size:{1}",
		*message, sizeOfAppLayerData), "message")

	L7, _ := json.Object("L7")
	L7.Set(sizeOfAppLayerData, "length")

	if sizeOfAppLayerData > 512 {
		L7.Set(string(appLayerData[:512-3])+"...", "sample")
	} else {
		L7.Set(string(appLayerData), "content")
	}

	return json, nil
}

func (t *JSONPcapTranslator) trySetHTTP(
	ctx context.Context,
	lock *flowLock,
	packet *gopacket.Packet,
	tcpFlags *uint8,
	appLayerData []byte,
	flowID *uint64,
	sequence *uint32,
	json *gabs.Container,
	message *string,
	tsp TraceAndSpanProvider,
) (*gabs.Container, bool) {
	isHTTP11Request := http11RequestPayloadRegex.Match(appLayerData)
	isHTTP11Response := !isHTTP11Request && http11ResponsePayloadRegex.Match(appLayerData)

	framer := http2.NewFramer(io.Discard, bytes.NewReader(appLayerData))
	frame, _ := framer.ReadFrame()

	// if content is not HTTP in clear text, abort
	if !isHTTP11Request && !isHTTP11Response && frame == nil {
		json.Set(*message, "message")
		return nil, false
	}

	// making at least 1 big assumption:
	//   HTTP request/status line and headers fit in 1 packet
	//     which is not always the case when fragmentation occurs
	L7, _ := json.Object("HTTP")

	streams := mapset.NewThreadUnsafeSet[uint32]()
	requestTS := make(map[uint32]*traceAndSpan)
	responseTS := make(map[uint32]*traceAndSpan)
	requestStreams := mapset.NewThreadUnsafeSet[uint32]()
	responseStreams := mapset.NewThreadUnsafeSet[uint32]()

	defer func() {
		if requestStreams.Cardinality() > 0 ||
			responseStreams.Cardinality() > 0 {
			lock.UnlockWithTraceAndSpan(
				requestStreams.ToSlice(),
				responseStreams.ToSlice(),
				requestTS, responseTS,
			)
		} else {
			lock.UnlockWithTCPFlags(tcpFlags)
		}
	}()

	// handle h2c traffic
	if frame != nil {
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
				if _ts := t.addHTTPHeaders(frameJSON, &headers); _ts != nil {
					_ts.streamID = &StreamID
					if isRequest {
						requestTS[StreamID] = _ts
						frameJSON.Set("request", "kind")
					} else if isResponse {
						responseTS[StreamID] = _ts
						frameJSON.Set("response", "kind")
					}
					t.setTraceAndSpan(json, _ts)
				} else if traced && isResponse {
					responseTS[StreamID] = ts
					t.setTraceAndSpan(json, ts)
				}

			case *http2.MetaHeadersFrame:
				frameJSON.Set("metadata", "type")
				mdJSON, _ := frameJSON.Object("metadata")
				for _, md := range frame.Fields {
					mdJSON.Set(md.Value, md.Name)
				}

			case *http2.DataFrame:
				frameJSON.Set("data", "type")
				data := frame.Data()
				sizeOfData := int64(sizeOfFrame)
				t.addHTTPBodyDetails(frameJSON, &sizeOfData, bytes.NewReader(data))
			}

			if isRequest {
				requestStreams.Add(StreamID)
			} else if isResponse {
				responseStreams.Add(StreamID)
			}

			// read next frame
			frame, _ = framer.ReadFrame()
		}

		L7.Set(streams.ToSlice(), "includes")

		json.Set(stringFormatter.Format("{0} | {1}", *message, "h2c"), "message")

		return json, true
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

	httpDataReader := bufio.NewReaderSize(bytes.NewReader(appLayerData), len(appLayerData))

	// attempt to parse HTTP/1.1 request
	if isHTTP11Request {
		requestStreams.Add(StreamID)
		request, err := http.ReadRequest(httpDataReader)
		if err == nil {
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
			t.addHTTPBodyDetails(L7, &request.ContentLength, request.Body)
			json.Set(stringFormatter.Format("{0} | {1} {2} {3}", *message, request.Proto, request.Method, url), "message")
			return L7, true
		}
	}

	// attempt to parse HTTP/1.1 response
	if isHTTP11Response {
		responseStreams.Add(StreamID)
		response, err := http.ReadResponse(httpDataReader, nil)
		if err == nil {
			L7.Set("response", "kind")
			L7.Set(response.Proto, "proto")
			L7.Set(response.StatusCode, "code")
			L7.Set(response.Status, "status")
			if _ts := t.addHTTPHeaders(L7, &response.Header); _ts != nil {
				_ts.streamID = &StreamID
				responseTS[StreamID] = _ts
				// include trace and span id for traceability
				t.setTraceAndSpan(json, _ts)
				if err := t.linkHTTP11ResponseToRequest(packet, flowID, L7, _ts); err != nil {
					io.WriteString(os.Stderr, err.Error()+"\n")
				}
			} else if traced {
				responseTS[StreamID] = ts
				t.setTraceAndSpan(json, ts)
				t.linkHTTP11ResponseToRequest(packet, flowID, L7, ts)
			}
			sizeOfBody := t.addHTTPBodyDetails(L7, &response.ContentLength, response.Body)
			if cl, err := strconv.ParseUint(response.Header.Get(httpContentLengthHeader), 10, 64); err == nil {
				// if content-length is greater than the size of body:
				//   - this HTTP message is fragmented and so there's more to come
				fragmented = cl > sizeOfBody
			}
			json.Set(stringFormatter.Format("{0} | {1} {2}",
				*message, response.Proto, response.Status), "message")
			return L7, true
		}
	}

	// fallback to a minimal (naive) attempt to parse HTTP/1.1
	// see: https://www.rfc-editor.org/rfc/rfc7540#section-8.1.3
	dataBytes := bytes.SplitN(appLayerData, http11BodySeparator, 2)
	// `parts` is everything before HTTP payload separator (`2*line-break`)
	//   - it includes: the HTTP line, and HTTP headers
	parts := bytes.Split(dataBytes[0], http11Separator)

	contentLength := uint64(0)

	var _ts *traceAndSpan = nil

	headers, _ := L7.Object("headers")
	// HTTP headers starts at `parts[1]`
	for _, header := range parts[1:] {
		headerParts := bytes.SplitN(header, http11HeaderSeparator, 2)
		nameBytes := bytes.TrimSpace(headerParts[0])
		value := string(bytes.TrimSpace(headerParts[1]))
		headers.Set(value, string(nameBytes))
		// include trace and span id for traceability
		switch {
		case bytes.EqualFold(nameBytes, traceparentHeaderBytes):
			if _ts = t.getTraceAndSpan(traceAndSpanRegex[traceparentHeader], &value); _ts != nil {
				_ts.streamID = &StreamID
				t.setTraceAndSpan(json, _ts)
			}

		case bytes.EqualFold(nameBytes, cloudTraceContextHeaderBytes):
			if _ts = t.getTraceAndSpan(traceAndSpanRegex[cloudTraceContextHeader], &value); _ts != nil {
				_ts.streamID = &StreamID
				t.setTraceAndSpan(json, _ts)
			}

		case bytes.EqualFold(nameBytes, httpContentLengthHeaderBytes):
			if cl, err := strconv.ParseUint(value, 10, 64); err == nil {
				contentLength = cl
			}
		}
	}

	if len(dataBytes) == 1 {
		return L7, false
	}

	bodyJSON, _ := L7.Object("body")
	sizeOfBody := uint64(0)
	sizeOfBody = uint64(len(dataBytes[1]))
	if sizeOfBody > 0 {
		bodyJSON.Set(string(dataBytes[1]), "data")
	}
	bodyJSON.Set(sizeOfBody, "length")

	fragmented = contentLength > sizeOfBody

	// `parts[0]` contains the HTTP line
	line := string(parts[0])
	L7.Set(line, "line")
	json.Set(stringFormatter.Format("{0} | {1}", *message, line), "message")

	if isHTTP11Request {
		requestStreams.Add(StreamID)
		requestParts := http11RequestPayloadRegex.FindStringSubmatch(line)
		L7.Set(requestParts[1], "method")
		L7.Set(requestParts[2], "url")
		host := "0"
		if _ts != nil {
			requestTS[StreamID] = _ts
			t.recordHTTP11Request(packet, flowID, sequence, _ts, &requestParts[1], &host, &requestParts[2])
		}
		return L7, true
	}

	// isHTTP11Response
	responseStreams.Add(StreamID)
	responseParts := http11ResponsePayloadRegex.FindStringSubmatch(line)
	if code, err := strconv.Atoi(responseParts[1]); err == nil {
		L7.Set(code, "code")
	} else {
		L7.Set(responseParts[1], "code")
	}
	L7.Set(responseParts[2], "status")
	if _ts != nil {
		responseTS[StreamID] = _ts
		if err := t.linkHTTP11ResponseToRequest(packet, flowID, L7, _ts); err != nil {
			io.WriteString(os.Stderr, err.Error()+"\n")
		}
	} else if traced {
		responseTS[StreamID] = ts
		t.setTraceAndSpan(json, ts)
		t.linkHTTP11ResponseToRequest(packet, flowID, L7, ts)
	}
	return L7, true
}

func (t *JSONPcapTranslator) addHTTPBodyDetails(L7 *gabs.Container, contentLength *int64, body io.Reader) uint64 {
	bodyBytes, err := io.ReadAll(body)
	if err != nil {
		return uint64(0)
	}

	bodyJSON, _ := L7.Object("body")

	sizeOfBody := uint64(len(bodyBytes))
	bodyLengthJSON, _ := bodyJSON.ArrayOfSize(2, "length")
	bodyLengthJSON.SetIndex(sizeOfBody, 0)
	bodyLengthJSON.SetIndex(*contentLength, 1)

	if sizeOfBody > 512 {
		bodyJSON.Set(string(bodyBytes[:512-3])+"...", "sample")
	} else {
		bodyJSON.Set(string(bodyBytes), "data")
	}

	return sizeOfBody
}

func (t *JSONPcapTranslator) recordHTTP11Request(packet *gopacket.Packet, flowID *uint64, sequence *uint32, ts *traceAndSpan, method, host, url *string) {
	fullURL := stringFormatter.Format("{0}{1}", *host, *url)
	_httpRequest := &httpRequest{
		timestamp: &(*packet).Metadata().Timestamp,
		method:    method,
		url:       &fullURL,
	}
	t.traceToHttpRequestMap.Set(*ts.traceID, _httpRequest)
}

func (t *JSONPcapTranslator) linkHTTP11ResponseToRequest(packet *gopacket.Packet, flowID *uint64, response *gabs.Container, ts *traceAndSpan) error {
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

func newJSONPcapTranslator(ctx context.Context, iface *PcapIface) *JSONPcapTranslator {
	// connection tracking data-structures
	flowToTimestamp := haxmap.New[uint64, *time.Time]()
	halfOpenFlows := mapset.NewSet[uint64]()
	halfClosedFlows := mapset.NewSet[uint64]()
	establishedFlows := mapset.NewSet[uint64]()

	flowToStreamToSequenceMap := haxmap.New[uint64, FTSM]()
	traceToHttpRequestMap := haxmap.New[string, *httpRequest]()
	flowMutex := newFlowMutex(ctx, flowToStreamToSequenceMap, traceToHttpRequestMap)

	return &JSONPcapTranslator{
		fm:                        flowMutex,
		iface:                     iface,
		traceToHttpRequestMap:     traceToHttpRequestMap,
		flowToTimestamp:           flowToTimestamp,
		halfOpenFlows:             halfOpenFlows,
		halfClosedFlows:           halfClosedFlows,
		establishedFlows:          establishedFlows,
		flowToStreamToSequenceMap: flowToStreamToSequenceMap,
	}
}
