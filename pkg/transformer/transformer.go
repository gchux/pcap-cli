package transformer

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
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

var transformerLogger = log.New(os.Stderr, "[transformer] - ", log.LstdFlags)

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
		done(context.Context)
	}

	PcapTransformer struct {
		ctx             context.Context
		iface           *PcapIface
		loggerPrefix    *string
		ich             chan concurrently.WorkFunction
		och             <-chan concurrently.OrderedOutput
		translator      PcapTranslator
		translatorPool  *ants.PoolWithFunc
		writerPool      *ants.MultiPoolWithFunc
		writers         []io.Writer
		numWriters      *uint8
		writeQueues     []chan *fmt.Stringer
		writeQueuesDone []chan struct{}
		wg              *sync.WaitGroup
		preserveOrder   bool
		connTracking    bool
		apply           func(*pcapTranslatorWorker) error
	}

	IPcapTransformer interface {
		WaitDone(context.Context, *time.Duration)
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
	tcpOptionsRegex               = `^TCPOption\((?P<name>.+?):(?P<value>.*?)\)$`
	http11RequestPayloadRegexStr  = `^(?P<method>.+?)\s(?P<url>.+?)\sHTTP/1\.1(?:\r?\n)?.*`
	http11ResponsePayloadRegexStr = `^HTTP/1\.1\s(?P<code>\d{3})\s(?P<status>.+?)(?:\r?\n)?.*`
	http2PrefaceRegexStr          = `^PRI.+?HTTP/2\.0\r?\n\r?\nSM\r?\n\r?\n`
	http11LineSeparator           = "\r\n"
	http2RawFrameRegexStr         = `^\[FrameHeader\s(.+?)\]`
	httpContentLengthHeader       = "Content-Length"
	cloudTraceContextHeader       = "x-cloud-trace-context"
	traceparentHeader             = "traceparent"

	// keeping it in sync with `h2`:
	//   - A stream identifier of zero (0x00) is used for connection control messages
	http11StreamID = uint32(1)
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
	http2PrefaceRegex            = regexp.MustCompile(http2PrefaceRegexStr)
	http2RawFrameRegex           = regexp.MustCompile(http2RawFrameRegexStr)
	http11Separator              = []byte(http11LineSeparator)
	http11BodySeparator          = []byte(http11LineSeparator + http11LineSeparator)
	http11HeaderSeparator        = []byte(":")
	httpContentLengthHeaderBytes = []byte(httpContentLengthHeader)
	cloudTraceContextHeaderBytes = []byte(cloudTraceContextHeader)
	traceparentHeaderBytes       = []byte(traceparentHeader)
	cloudProjectID               = os.Getenv(projectIdEnvVarName)
	cloudTracePrefix             = "projects/" + cloudProjectID + "/traces/"

	traceAndSpanRegexStr = map[string]string{
		cloudTraceContextHeader: `^(?P<trace>.+?)/(?P<span>.+?)(?:;o=.*)?$`,
		traceparentHeader:       `^.+?-(?P<trace>.+?)-(?P<span>.+?)(?:-.+)?$`,
	}
	traceAndSpanRegex = map[string]*regexp.Regexp{
		cloudTraceContextHeader: regexp.MustCompile(traceAndSpanRegexStr[cloudTraceContextHeader]),
		traceparentHeader:       regexp.MustCompile(traceAndSpanRegexStr[traceparentHeader]),
	}
)

var (
	errUnavailableTranslation = errors.New("packet translation is unavailable")
	errUnavailableTranslator  = errors.New("translator is unavailable")
)

func (t *PcapTransformer) writeTranslation(ctx context.Context, task *pcapWriteTask) error {
	defer t.wg.Done()
	select {
	case <-ctx.Done():
		if *task.writer == 0 {
			// best-effort: dump all non-written translations into `STDERR`
			fmt.Fprintln(os.Stderr, (*task.translation).String())
		}
		return ctx.Err()
	default:
		_, err := t.translator.write(ctx, t.writers[*task.writer], task.translation)
		return err
	}
}

func (t *PcapTransformer) publishTranslation(_ context.Context, translation *fmt.Stringer) error {
	if translation == nil {
		// if `translation` is not available, rollback write commitment
		for range *t.numWriters {
			t.wg.Done()
		}
		return errors.Join(errUnavailableTranslation, errors.New(*t.loggerPrefix+"nil translation"))
	}

	// fan-out translation into all writers
	for _, translations := range t.writeQueues {
		// if any of the consumers' buffers is full,
		// the saturated/slower one will block and delay iterations.
		// Blocking is more likely when `preserveOrder` is enabled.
		translations <- translation
	}
	return nil
}

func (t *PcapTransformer) produceTranslation(ctx context.Context, task *pcapTranslatorWorker) error {
	return t.publishTranslation(ctx, task.Run(ctx).(*fmt.Stringer))
}

func (t *PcapTransformer) produceTranslations(ctx context.Context) {
	for translation := range t.och {
		// translations are made available in the enqueued order
		// consume translations and push them into translations consumers
		t.publishTranslation(ctx, translation.Value.(*fmt.Stringer))
	}
}

func (t *PcapTransformer) consumeTranslations(ctx context.Context, index *uint8) error {
	// `consumeTranslations` runs in 1 goroutine per writer,
	// so it needs to be context aware to be able to gracefully stop, thus preventing a leak.
	for {
		select {
		case <-ctx.Done():
			// drop translations if context is already done
			droppedTranslations := uint32(0)
			// some translations may have been on-going when context was cancelled:
			//   - fully consume the `writerQueue` and rollback the write commitment,
			//   - block until `close` on the `writerQueue` is called by `WaitDone`
			for translation := range t.writeQueues[*index] {
				// best-effort: dump all non-written translations into `STDERR`
				if *index == 0 {
					fmt.Fprintln(os.Stderr, (*translation).String())
				}
				droppedTranslations += 1
				t.wg.Done()
			}
			transformerLogger.Printf("%s writer:%d | dropped translations: %d\n", *t.loggerPrefix, *index+1, droppedTranslations)
			close(t.writeQueuesDone[*index])
			return ctx.Err()

		case translation := <-t.writeQueues[*index]:
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
}

func (t *PcapTransformer) waitForContextDone(ctx context.Context) error {
	<-ctx.Done()
	close(t.ich)
	return ctx.Err()
}

// returns when all packets have been transformed and written
func (t *PcapTransformer) WaitDone(ctx context.Context, timeout *time.Duration) {
	ts := time.Now()
	timer := time.NewTimer(*timeout)

	writeDoneChan := make(chan struct{})

	go func() {
		if !t.preserveOrder && !t.connTracking {
			transformerLogger.Printf("%s gracefully terminating | tp: %d/%d | wp: %d/%d | deadline: %v\n",
				*t.loggerPrefix, t.translatorPool.Running(), t.translatorPool.Waiting(), t.writerPool.Running(), t.writerPool.Waiting(), timeout)
		} else {
			transformerLogger.Printf("%s gracefully terminating | deadline: %v\n", *t.loggerPrefix, timeout)
		}
		t.wg.Wait() // wait for all translations to be written
		close(writeDoneChan)
	}()

	select {
	case <-timer.C:
		if !t.preserveOrder && !t.connTracking {
			transformerLogger.Printf("%s timed out waiting for graceful termination | tp: %d/%d | wp: %d/%d\n",
				*t.loggerPrefix, t.translatorPool.Running(), t.translatorPool.Waiting(), t.writerPool.Running(), t.writerPool.Waiting())
		} else {
			transformerLogger.Printf("%s timed out waiting for graceful termination\n", *t.loggerPrefix)
		}
		for i, writeQueue := range t.writeQueues {
			close(writeQueue) // close writer channels
			close(t.writeQueuesDone[i])
		}
		t.translator.done(ctx)
		return

	case <-writeDoneChan:
		timer.Stop()
		transformerLogger.Printf("%s STOPPED – %v\n", *t.loggerPrefix, time.Since(ts))
	}

	for i, writeQueue := range t.writeQueues {
		// unblock `consumeTranslations` goroutines
		close(writeQueue) // close writer channels
		<-t.writeQueuesDone[i]
	}

	_timeout := *timeout - time.Since(ts)
	// if order is not enforced: there are 2 worker pools to be stopped
	if _timeout > 0 && !t.preserveOrder && !t.connTracking {
		transformerLogger.Printf("%s releasing worker pools | deadline: %v\n", *t.loggerPrefix, _timeout)
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			t.translatorPool.ReleaseTimeout(_timeout)
			wg.Done()
		}()
		go func() {
			t.writerPool.ReleaseTimeout(_timeout)
			wg.Done()
		}()
		wg.Wait()
		transformerLogger.Printf("%s released worker pools\n", *t.loggerPrefix)
	}

	// only safe to be called when nothing else is running
	t.translator.done(ctx)

	transformerLogger.Printf("%s TERMINATED | latency: %v\n", *t.loggerPrefix, time.Since(ts))
}

func (t *PcapTransformer) Apply(ctx context.Context, packet *gopacket.Packet, serial *uint64) error {
	select {
	case <-ctx.Done():
		// reject applying transformer if context is already done.
		return ctx.Err()
	default:
		// applying transformer will write 1 translation into N>0 writers.
		t.wg.Add(int(*t.numWriters))
	}
	// It is assumed that packets will be produced faster than translations and writing operations, so:
	//   - process/translate packets concurrently in order to avoid blocking `gopacket` packets channel as much as possible.
	worker := newPcapTranslatorWorker(serial, packet, t.translator, t.connTracking)
	return t.apply(worker)
}

func (t *PcapTransformer) translatePacketFn(ctx context.Context, worker interface{}) error {
	select {
	case <-ctx.Done():
		// rollback write packet translation commitment
		for range *t.numWriters {
			t.wg.Done()
		}
		return ctx.Err()
	default:
		return t.produceTranslation(ctx, worker.(*pcapTranslatorWorker))
	}
}

func (t *PcapTransformer) writeTranslationFn(ctx context.Context, task interface{}) error {
	return t.writeTranslation(ctx, task.(*pcapWriteTask))
}

func newTranslator(
	ctx context.Context,
	debug bool,
	iface *PcapIface,
	format PcapTranslatorFmt,
) (PcapTranslator, error) {
	switch format {
	case JSON:
		return newJSONPcapTranslator(ctx, debug, iface), nil
	case TEXT:
		return newTextPcapTranslator(iface), nil
	case PROTO:
		return newProtoPcapTranslator(iface), nil
	default:
		/* no-go */
	}

	return nil, errors.Join(errUnavailableTranslator,
		fmt.Errorf("[%d/%s] - format: %v", iface.Index, iface.Name, format))
}

// if preserving packet capture order is not required, translations may be done concurrently
// concurrently translating packets means that translations are not enqueded in packet capture order.
// Similarly, sinking translations into files can be safely done concurrently ( in whatever order goroutines are scheduled )
func provideWorkerPools(ctx context.Context, transformer *PcapTransformer, numWriters *uint8) {
	poolOpts := ants.Options{
		PreAlloc:       true,
		Nonblocking:    false,
		ExpiryDuration: 10 * time.Second,
	}

	poolOpts.PanicHandler = func(i interface{}) {
		transformerLogger.Printf("%s panic: %v\n", *transformer.loggerPrefix, i)
		for range *transformer.numWriters {
			transformer.wg.Done()
		}
	}

	poolOptions := ants.WithOptions(poolOpts)

	poolSize := 25 * int(*numWriters)

	translatorPoolFn := func(i interface{}) {
		transformer.translatePacketFn(ctx, i)
	}
	translatorPool, _ := ants.NewPoolWithFunc(poolSize, translatorPoolFn, poolOptions)
	transformer.translatorPool = translatorPool

	writerPoolFn := func(i interface{}) {
		transformer.writeTranslationFn(ctx, i)
	}

	// I/O ( writing ) is slow; so there will be more writers than translator routines
	writerPool, _ := ants.NewMultiPoolWithFunc(int(*numWriters), 25, writerPoolFn, ants.LeastTasks, poolOptions)
	transformer.writerPool = writerPool
}

func provideConcurrentQueue(ctx context.Context, connTrack bool, transformer *PcapTransformer, numWriters *uint8) {
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
		poolSize = 30 * int(*numWriters)
	}

	ochOpts := &concurrently.Options{
		PoolSize:         poolSize,
		OutChannelBuffer: 100,
	}

	transformer.ich = make(chan concurrently.WorkFunction, 100)
	transformer.och = concurrently.Process(ctx, transformer.ich, ochOpts)
}

func provideStrategy(ctx context.Context, transformer *PcapTransformer, preserveOrder, connTracking bool) {
	var strategy func(*pcapTranslatorWorker) error

	if preserveOrder || connTracking {
		// If ordered output is enabled, enqueue translation workers in packet capture order;
		// this will introduce some level of contention as the translation Q starts to fill (saturation):
		// if the next packet to arrive finds a full Q, this method will block until slots are available.
		// The degree of contention is proportial to the Q capacity times translation latency.
		// Order should only be used for not network intersive workloads.
		strategy = func(worker *pcapTranslatorWorker) error {
			select {
			case <-ctx.Done():
				// `Apply` commits `transformer` to write the packet translation,
				// so if the context is done, commitment must be rolled back
				for range *transformer.numWriters {
					transformer.wg.Done()
				}
				return ctx.Err()
			default:
				transformer.ich <- worker
			}
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
func newTransformer(
	ctx context.Context,
	iface *PcapIface,
	writers []io.Writer,
	format *string,
	preserveOrder,
	connTracking bool,
	debug bool,
) (IPcapTransformer, error) {
	pcapFmt := pcapTranslatorFmts[*format]
	translator, err := newTranslator(ctx, debug, iface, pcapFmt)
	if err != nil {
		return nil, err
	}

	loggerPrefix := fmt.Sprintf("[%d/%s] -", iface.Index, iface.Name)

	numWriters := uint8(len(writers))
	// not using `io.MultiWriter` as it writes to all writers sequentially
	writeQueues := make([]chan *fmt.Stringer, numWriters)
	writeQueuesDone := make([]chan struct{}, numWriters)
	for i := range writers {
		writeQueues[i] = make(chan *fmt.Stringer, 100)
		writeQueuesDone[i] = make(chan struct{})
	}

	// same transformer, multiple strategies
	// via multiple translator implementations
	transformer := &PcapTransformer{
		wg:              new(sync.WaitGroup),
		ctx:             ctx,
		iface:           iface,
		loggerPrefix:    &loggerPrefix,
		translator:      translator,
		writers:         writers,
		numWriters:      &numWriters,
		writeQueues:     writeQueues,
		writeQueuesDone: writeQueuesDone,
		preserveOrder:   preserveOrder || connTracking,
		connTracking:    connTracking,
	}

	provideStrategy(ctx, transformer, preserveOrder, connTracking)

	// `preserveOrder==true` causes writes to be sequential and blocking per `io.Writer`.
	// `preserveOrder==true` although blocking at writting, does not cause `transformer.Apply` to block.
	if preserveOrder || connTracking {
		provideConcurrentQueue(ctx, connTracking, transformer, &numWriters)
		go transformer.waitForContextDone(ctx)
		go transformer.produceTranslations(ctx)
	} else {
		provideWorkerPools(ctx, transformer, &numWriters)
	}

	// spawn consumers for all `io.Writer`s
	// 1 consumer goroutine per `io.Writer`
	for i := range writeQueues {
		index := uint8(i)
		go transformer.consumeTranslations(ctx, &index)
	}

	transformerLogger.Printf("%s CREATED | format:%s | writers:%d\n", loggerPrefix, *format, numWriters)

	return transformer, nil
}

func NewOrderedTransformer(ctx context.Context, iface *PcapIface, writers []io.Writer, format *string, debug bool) (IPcapTransformer, error) {
	return newTransformer(ctx, iface, writers, format, true /* preserveOrder */, false /* connTracking */, debug)
}

func NewConnTrackTransformer(ctx context.Context, iface *PcapIface, writers []io.Writer, format *string, debug bool) (IPcapTransformer, error) {
	return newTransformer(ctx, iface, writers, format, true /* preserveOrder */, true /* connTracking */, debug)
}

func NewDebugTransformer(ctx context.Context, iface *PcapIface, writers []io.Writer, format *string) (IPcapTransformer, error) {
	return newTransformer(ctx, iface, writers, format, false /* preserveOrder */, false /* connTracking */, true /* debug */)
}

func NewTransformer(ctx context.Context, iface *PcapIface, writers []io.Writer, format *string, debug bool) (IPcapTransformer, error) {
	return newTransformer(ctx, iface, writers, format, false /* preserveOrder */, false /* connTracking */, debug)
}
