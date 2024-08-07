package transformer

import (
	"context"
	"fmt"
	"io"
	"os"
	"regexp"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/panjf2000/ants/v2"
	concurrently "github.com/tejzpr/ordered-concurrently/v3"
)

type (
	PcapTranslatorFmt uint8

	PcapTranslator interface {
		next(context.Context, *uint64, *gopacket.Packet) fmt.Stringer
		translateEthernetLayer(context.Context, *layers.Ethernet) fmt.Stringer
		translateIPv4Layer(context.Context, *layers.IPv4) fmt.Stringer
		translateIPv6Layer(context.Context, *layers.IPv6) fmt.Stringer
		translateUDPLayer(context.Context, *layers.UDP) fmt.Stringer
		translateTCPLayer(context.Context, *layers.TCP) fmt.Stringer
		translateTLSLayer(context.Context, *layers.TLS) fmt.Stringer
		translateDNSLayer(context.Context, *layers.DNS) fmt.Stringer
		merge(context.Context, fmt.Stringer, fmt.Stringer) (fmt.Stringer, error)
		finalize(context.Context, *uint64, *gopacket.Packet, bool, fmt.Stringer) (fmt.Stringer, error)
		write(context.Context, io.Writer, *fmt.Stringer) (int, error)
	}

	PcapTransformer struct {
		ctx            context.Context
		iface          *PcapIface
		ich            chan concurrently.WorkFunction
		och            <-chan concurrently.OrderedOutput
		translator     PcapTranslator
		translatorPool *ants.PoolWithFunc
		writerPool     *ants.MultiPoolWithFunc
		writers        []io.Writer
		writeQueues    []chan *fmt.Stringer
		wg             *sync.WaitGroup
		preserveOrder  bool
		connTracking   bool
		apply          func(*pcapTranslatorWorker) error
	}

	IPcapTransformer interface {
		WaitDone()
		Apply(context.Context, *gopacket.Packet, *uint64) error
	}

	pcapWriteTask struct {
		ctx         context.Context
		writer      *uint8
		translation *fmt.Stringer
	}

	PcapIface struct {
		Index int
		Name  string
		Addrs []pcap.InterfaceAddress
	}

	ContextKey string
)

const (
	ContextID      = ContextKey("id")
	ContextLogName = ContextKey("logName")
)

//go:generate stringer -type=PcapTranslatorFmt
const (
	TEXT PcapTranslatorFmt = iota
	JSON
	PROTO
)

var pcapTranslatorFmts = map[string]PcapTranslatorFmt{
	"json":  JSON,
	"text":  TEXT,
	"proto": PROTO,
}

const (
	projectIdEnvVarName           = "PROJECT_ID"
	tcpOptionsRegex               = `^TCPOption\((?P<opt>.*?)\)$`
	http11RequestPayloadRegexStr  = `^(?P<method>.+?)\s(?P<url>.+?)\sHTTP/1\.1(?:\r?\n)?.*`
	http11ResponsePayloadRegexStr = `^HTTP/1\.1\s(?P<code>\d{3})\s(?P<status>.+?)(?:\r?\n)?.*`
	http11LineSeparator           = "\r\n"
	cloudTraceContextHeader       = "X-Cloud-Trace-Context"
	traceAndSpanRegexStr          = `^(?P<trace>.+?)/(?P<span>.+?)(?:;o=.*)?$`
)

var (
	tcpSynStr = "SYN"
	tcpAckStr = "ACK"
	tcpPshStr = "PSH"
	tcpFinStr = "FIN"
	tcpRstStr = "RST"
	tcpUrgStr = "URG"
	tcpEceStr = "ECE"
	tcpCwrStr = "CWR"

	tcpFlags = map[string]uint8{
		tcpFinStr: 0b00000001,
		tcpSynStr: 0b00000010,
		tcpRstStr: 0b00000100,
		tcpPshStr: 0b00001000,
		tcpAckStr: 0b00010000,
		tcpUrgStr: 0b00100000,
		tcpEceStr: 0b01000000,
		tcpCwrStr: 0b10000000,
	}

	tcpSynAckStr    = tcpSynStr + "|" + tcpAckStr
	tcpSynRstStr    = tcpSynStr + "|" + tcpRstStr
	tcpPshAckStr    = tcpPshStr + "|" + tcpAckStr
	tcpFinAckStr    = tcpFinStr + "|" + tcpAckStr
	tcpRstAckStr    = tcpRstStr + "|" + tcpAckStr
	tcpUrgAckStr    = tcpUrgStr + "|" + tcpAckStr
	tcpSynPshAckStr = tcpSynStr + "|" + tcpPshStr + "|" + tcpAckStr
	tcpFinRstAckStr = tcpFinStr + "|" + tcpRstStr + "|" + tcpAckStr

	tcpSyn = tcpFlags[tcpSynStr]
	tcpAck = tcpFlags[tcpAckStr]
	tcpPsh = tcpFlags[tcpPshStr]
	tcpFin = tcpFlags[tcpFinStr]
	tcpRst = tcpFlags[tcpRstStr]
	tcpUrg = tcpFlags[tcpUrgStr]
	tcpEce = tcpFlags[tcpEceStr]
	tcpCwr = tcpFlags[tcpCwrStr]

	tcpSynAck    = tcpSyn | tcpAck
	tcpSynRst    = tcpSyn | tcpRst
	tcpPshAck    = tcpPsh | tcpAck
	tcpFinAck    = tcpFin | tcpAck
	tcpRstAck    = tcpRst | tcpAck
	tcpUrgAck    = tcpUrg | tcpAck
	tcpSynPshAck = tcpSyn | tcpPsh | tcpAck
	tcpFinRstAck = tcpFin | tcpRst | tcpAck

	tcpFlagsStr = map[uint8]string{
		tcpSyn:       tcpSynStr,
		tcpAck:       tcpAckStr,
		tcpPsh:       tcpPshStr,
		tcpFin:       tcpFinStr,
		tcpRst:       tcpRstStr,
		tcpUrg:       tcpUrgStr,
		tcpEce:       tcpEceStr,
		tcpCwr:       tcpCwrStr,
		tcpSynAck:    tcpSynAckStr,
		tcpSynRst:    tcpSynRstStr,
		tcpPshAck:    tcpPshAckStr,
		tcpFinAck:    tcpFinAckStr,
		tcpRstAck:    tcpRstAckStr,
		tcpUrgAck:    tcpUrgAckStr,
		tcpSynPshAck: tcpSynPshAckStr,
		tcpFinRstAck: tcpFinRstAckStr,
	}
)

var (
	tcpOptionRgx                 = regexp.MustCompile(tcpOptionsRegex)
	http11RequestPayloadRegex    = regexp.MustCompile(http11RequestPayloadRegexStr)
	http11ResponsePayloadRegex   = regexp.MustCompile(http11ResponsePayloadRegexStr)
	http11Separator              = []byte(http11LineSeparator)
	http11BodySeparator          = []byte(http11LineSeparator + http11LineSeparator)
	http11HeaderSeparator        = []byte(":")
	cloudTraceContextHeaderBytes = []byte(cloudTraceContextHeader)
	traceAndSpanRegex            = regexp.MustCompile(traceAndSpanRegexStr)
	cloudProjectID               = os.Getenv(projectIdEnvVarName)
	cloudTracePrefix             = "projects/" + cloudProjectID + "/traces/"
)

func (t *PcapTransformer) writeTranslation(ctx context.Context, task *pcapWriteTask) {
	// consume translations – flush them into writers
	// io.WriteString(task.writer, (*task.translation).String()+"\n")
	t.translator.write(ctx, t.writers[*task.writer], task.translation)
	t.wg.Done()
}

func (t *PcapTransformer) publishTranslation(ctx context.Context, translation *fmt.Stringer) {
	for _, translations := range t.writeQueues {
		// if any of the consumers' buffers is full,
		// the saturated/slower one will block and delay iterations.
		// Blocking is more likely when `preserveOrder` is enabled.
		translations <- translation
	}
}

func (t *PcapTransformer) produceTranslation(ctx context.Context, task *pcapTranslatorWorker) error {
	t.publishTranslation(ctx, task.Run(ctx).(*fmt.Stringer))
	return nil
}

func (t *PcapTransformer) produceTranslations(ctx context.Context) {
	// translations are made available in the enqueued order
	for translation := range t.och {
		// consume translations and push them into translations consumers
		t.publishTranslation(ctx, translation.Value.(*fmt.Stringer))
	}
}

func (t *PcapTransformer) consumeTranslations(ctx context.Context, index *uint8) {
	for translation := range t.writeQueues[*index] {
		task := &pcapWriteTask{
			ctx:         ctx,
			writer:      index,
			translation: translation,
		}

		if t.preserveOrder || t.connTracking {
			// this is mostly blocking
			t.writeTranslation(ctx, task)
		} else {
			// this is mostly non-blocking
			t.writerPool.Invoke(task)
		}
	}
}

func (t *PcapTransformer) waitForContextDone(ctx context.Context) {
	<-ctx.Done()
	close(t.ich)
}

// returns when all packets have been transformed and written
func (t *PcapTransformer) WaitDone() {
	t.wg.Wait() // wait for all translations to be written
	for _, writeQueue := range t.writeQueues {
		close(writeQueue) // close writer channels
	}
	// if order is not enforced: there are 2 worker pools to be stopped
	if !t.preserveOrder {
		t.translatorPool.Release()
		t.writerPool.ReleaseTimeout(5 * time.Second)
	}
}

func (t *PcapTransformer) Apply(ctx context.Context, packet *gopacket.Packet, serial *uint64) error {
	// It is assumed that packets will be produced faster than translations and writing operations, so:
	//   - process/translate packets concurrently in order to avoid blocking `gopacket` packets channel as much as possible.
	worker := newPcapTranslatorWorker(serial, packet, t.translator, t.connTracking)
	t.wg.Add(len(t.writers))
	return t.apply(worker)
}

func (t *PcapTransformer) translatePacketFn(ctx context.Context, worker interface{}) {
	t.produceTranslation(ctx, worker.(*pcapTranslatorWorker))
}

func (t *PcapTransformer) writeTranslationFn(ctx context.Context, task interface{}) {
	t.writeTranslation(ctx, task.(*pcapWriteTask))
}

func newTranslator(iface *PcapIface, format PcapTranslatorFmt) (PcapTranslator, error) {
	switch format {
	case JSON:
		return newJSONPcapTranslator(iface), nil
	case TEXT:
		return newTextPcapTranslator(iface), nil
	case PROTO:
		return newProtoPcapTranslator(iface), nil
	default:
		/* no-go */
	}

	return nil, fmt.Errorf("translator unavailable: %v", format)
}

// if preserving packet capture order is not required, translations may be done concurrently
// concurrently translating packets means that translations are not enqueded in packet capture order.
// Similarly, sinking translations into files can be safely done concurrently ( in whatever order goroutines are scheduled )
func provideWorkerPools(ctx context.Context, transformer *PcapTransformer, numWriters int) {
	poolOpts := ants.Options{
		PreAlloc:       true,
		Nonblocking:    false,
		ExpiryDuration: 10 * time.Second,
	}
	poolOpt := ants.WithOptions(poolOpts)

	poolSize := 20 * numWriters

	translatorPoolFn := func(i interface{}) {
		transformer.translatePacketFn(ctx, i)
	}
	translatorPool, _ := ants.NewPoolWithFunc(poolSize, translatorPoolFn, poolOpt)
	transformer.translatorPool = translatorPool

	writerPoolFn := func(i interface{}) {
		transformer.writeTranslationFn(ctx, i)
	}

	// I/O ( writing ) is slow; so there will be more writers than translator routines
	writerPool, _ := ants.NewMultiPoolWithFunc(numWriters, poolSize, writerPoolFn, ants.LeastTasks, poolOpt)
	transformer.writerPool = writerPool
}

func provideConcurrentQueue(ctx context.Context, connTrack bool, transformer *PcapTransformer, numWriters int) {
	// if connection tracking is enabled, the whole process is synchronous,
	// so the following considerations apply:
	//   - should be enabled only in combination with a very specific filter
	//   - should not be used when high traffic rate is expected:
	//       non-concurrent processing is slower, so more memory is required to buffer packets
	poolSize := 1
	if !connTrack {
		// when `poolSize` is greater than 1: even when written in order,
		// packets are processed concurrently which makes connection tracking
		// a very complex process to be done on-the-fly as order of packet translation
		// is not guaranteed; introducing contention may slow down the whole process.
		poolSize = 30 * numWriters
	}

	ochOpts := &concurrently.Options{
		PoolSize:         poolSize,
		OutChannelBuffer: 100,
	}

	transformer.ich = make(chan concurrently.WorkFunction, 100)
	transformer.och = concurrently.Process(ctx, transformer.ich, ochOpts)
}

func provideStrategy(transformer *PcapTransformer, preserveOrder, connTracking bool) {
	var strategy func(*pcapTranslatorWorker) error

	if preserveOrder || connTracking {
		// If ordered output is enabled, enqueue translation workers in packet capture order;
		// this will introduce some level of contention as the translation Q starts to fill (saturation):
		// if the next packet to arrive finds a full Q, this method will block until slots are available.
		// The degree of contention is proportial to the Q capacity times translation latency.
		// Order should only be used for not network intersive workloads.
		strategy = func(worker *pcapTranslatorWorker) error {
			transformer.ich <- worker
			return nil
		}
	} else {
		// if ordered output is disabled, translate packets concurrently via translator pool.
		// Order of gorouting execution is not guaranteed, which means
		// that packets will be consumed/written in non-deterministic order.
		// `serial` is aviailable to be used for sorting PCAP files.
		strategy = func(worker *pcapTranslatorWorker) error {
			return transformer.translatorPool.Invoke(worker)
		}
	}

	transformer.apply = strategy
}

// transformers get instances of `io.Writer` instead of `pcap.PcapWriter` to prevent closing.
func newTransformer(ctx context.Context, iface *PcapIface, writers []io.Writer, format *string, preserveOrder, connTracking bool) (IPcapTransformer, error) {
	pcapFmt := pcapTranslatorFmts[*format]
	translator, err := newTranslator(iface, pcapFmt)
	if err != nil {
		return nil, err
	}

	numWriters := len(writers)
	// not using `io.MultiWriter` as it writes to all writers sequentially
	writeQueues := make([]chan *fmt.Stringer, numWriters)
	for i := range writers {
		writeQueues[i] = make(chan *fmt.Stringer, 10*numWriters)
	}

	// same transformer, multiple strategies
	// via multiple translator implementations
	transformer := &PcapTransformer{
		wg:            new(sync.WaitGroup),
		ctx:           ctx,
		iface:         iface,
		translator:    translator,
		writers:       writers,
		writeQueues:   writeQueues,
		preserveOrder: preserveOrder || connTracking,
		connTracking:  connTracking,
	}

	provideStrategy(transformer, preserveOrder, connTracking)

	// `preserveOrder==true` causes writes to be sequential and blocking per `io.Writer`.
	// `preserveOrder==true` although blocking at writting, does not cause `transformer.Apply` to block.
	if preserveOrder || connTracking {
		provideConcurrentQueue(ctx, connTracking, transformer, numWriters)
		go transformer.waitForContextDone(ctx)
		go transformer.produceTranslations(ctx)
	} else {
		provideWorkerPools(ctx, transformer, numWriters)
	}

	// spawn consumers for all `io.Writer`s
	// 1 consumer goroutine per `io.Writer`
	for i := range writeQueues {
		index := uint8(i)
		go transformer.consumeTranslations(ctx, &index)
	}

	return transformer, nil
}

func NewOrderedTransformer(ctx context.Context, iface *PcapIface, writers []io.Writer, format *string) (IPcapTransformer, error) {
	return newTransformer(ctx, iface, writers, format, true /* preserveOrder */, false /* connTracking */)
}

func NewConnTrackTransformer(ctx context.Context, iface *PcapIface, writers []io.Writer, format *string) (IPcapTransformer, error) {
	return newTransformer(ctx, iface, writers, format, true /* preserveOrder */, true /* connTracking */)
}

func NewTransformer(ctx context.Context, iface *PcapIface, writers []io.Writer, format *string) (IPcapTransformer, error) {
	return newTransformer(ctx, iface, writers, format, false /* preserveOrder */, false /* connTracking */)
}
