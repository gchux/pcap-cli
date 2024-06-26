package transformer

import (
	"context"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	gpcap "github.com/google/gopacket/pcap"
	"github.com/panjf2000/ants/v2"
	concurrently "github.com/tejzpr/ordered-concurrently/v3"
)

var tcpFlagNames = []string{"SYN", "ACK", "PSH", "FIN", "RST", "URG", "ECE", "CWR"}

type (
	PcapTranslatorFmt int

	PcapTranslator interface {
		next(context.Context, *gopacket.Packet, *uint64) fmt.Stringer
		translateEthernetLayer(context.Context, *layers.Ethernet) fmt.Stringer
		translateIPv4Layer(context.Context, *layers.IPv4) fmt.Stringer
		translateIPv6Layer(context.Context, *layers.IPv6) fmt.Stringer
		translateUDPLayer(context.Context, *layers.UDP) fmt.Stringer
		translateTCPLayer(context.Context, *layers.TCP) fmt.Stringer
		translateTLSLayer(context.Context, *layers.TLS) fmt.Stringer
		translateDNSLayer(context.Context, *layers.DNS) fmt.Stringer
		merge(context.Context, fmt.Stringer, fmt.Stringer) (fmt.Stringer, error)
		finalize(context.Context, fmt.Stringer) (fmt.Stringer, error)
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
		apply          func(*pcapTranslatorWorker) error
	}

	IPcapTransformer interface {
		WaitDone()
		Apply(context.Context, *gopacket.Packet, *uint64) error
	}

	pcapWriteTask struct {
		ctx         context.Context
		writer      io.Writer
		translation *fmt.Stringer
	}

	PcapIface struct {
		Index int
		Name  string
		Addrs []gpcap.InterfaceAddress
	}

	ContextKey string
)

const (
	ContextID      = ContextKey("id")
	ContextLogName = ContextKey("logName")
)

func (t *PcapTransformer) writeTranslation(ctx context.Context, task *pcapWriteTask) {
	// consume translations – flush them into writers
	// io.WriteString(task.writer, (*task.translation).String()+"\n")
	t.translator.write(ctx, task.writer, task.translation)
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

func (t *PcapTransformer) consumeTranslations(ctx context.Context, index int) {
	for translation := range t.writeQueues[index] {
		task := &pcapWriteTask{
			ctx:         ctx,
			writer:      t.writers[index],
			translation: translation,
		}

		if t.preserveOrder {
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
	// if order is not enforced, there are not worker pools to be stopped
	if !t.preserveOrder {
		t.translatorPool.Release()
		t.writerPool.ReleaseTimeout(0)
	}
}

func (t *PcapTransformer) Apply(ctx context.Context, packet *gopacket.Packet, serial *uint64) error {
	// It is assumed that packets will be produced faster than translations.
	// process/translate packets concurrently in order to avoid blocking `gopacket` packets channel.
	worker := &pcapTranslatorWorker{
		serial:     serial,
		packet:     packet,
		translator: t.translator,
	}
	t.wg.Add(len(t.writers))
	return t.apply(worker)
}

func translatePacket(ctx context.Context, transformer *PcapTransformer, worker interface{}) {
	transformer.produceTranslation(ctx, worker.(*pcapTranslatorWorker))
}

func writeTranslation(ctx context.Context, transformer *PcapTransformer, task interface{}) {
	transformer.writeTranslation(ctx, task.(*pcapWriteTask))
}

func newTranslator(iface *PcapIface, format PcapTranslatorFmt) (PcapTranslator, error) {
	switch format {
	case JSON:
		return newJSONPcapTranslator(iface), nil
	case TEXT:
		return newTextPcapTranslator(iface), nil
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
		ExpiryDuration: 5 * time.Second,
	}
	poolOpt := ants.WithOptions(poolOpts)

	poolSize := 10 * numWriters

	translatorPoolFn := func(i interface{}) {
		translatePacket(ctx, transformer, i)
	}
	translatorPool, _ := ants.NewPoolWithFunc(poolSize, translatorPoolFn, poolOpt)
	transformer.translatorPool = translatorPool

	writerPoolFn := func(i interface{}) {
		writeTranslation(ctx, transformer, i)
	}
	writerPool, _ := ants.NewMultiPoolWithFunc(numWriters, poolSize, writerPoolFn, ants.LeastTasks, poolOpt)
	transformer.writerPool = writerPool
}

func provideConcurrentQueue(ctx context.Context, transformer *PcapTransformer, numWriters int) {
	queueSize := 20 * numWriters

	ochOpts := &concurrently.Options{
		PoolSize:         queueSize,
		OutChannelBuffer: queueSize,
	}

	transformer.ich = make(chan concurrently.WorkFunction, queueSize)
	transformer.och = concurrently.Process(ctx, transformer.ich, ochOpts)
}

func provideStrategy(transformer *PcapTransformer, preserveOrder bool) {
	var strategy func(*pcapTranslatorWorker) error

	if preserveOrder {
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
func newTransformer(ctx context.Context, iface *PcapIface, writers []io.Writer, format *string, preserveOrder bool) (IPcapTransformer, error) {
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
		preserveOrder: preserveOrder,
	}

	provideStrategy(transformer, preserveOrder)

	// `preserveOrder==true` causes writes to be sequential and blocking per `io.Writer`.
	// `preserveOrder==true` although blocking at writting, does not cause `transformer.Apply` to block.
	if preserveOrder {
		provideConcurrentQueue(ctx, transformer, numWriters)
		go transformer.waitForContextDone(ctx)
		go transformer.produceTranslations(ctx)
	} else {
		provideWorkerPools(ctx, transformer, numWriters)
	}

	// spawn consumers for all `io.Writer`s
	// 1 consumer goroutine per `io.Writer`
	for i := range writeQueues {
		go transformer.consumeTranslations(ctx, i)
	}

	return transformer, nil
}

func NewOrderedTransformer(ctx context.Context, iface *PcapIface, writers []io.Writer, format *string) (IPcapTransformer, error) {
	return newTransformer(ctx, iface, writers, format, true /* preserveOrder */)
}

func NewTransformer(ctx context.Context, iface *PcapIface, writers []io.Writer, format *string) (IPcapTransformer, error) {
	return newTransformer(ctx, iface, writers, format, false /* preserveOrder */)
}
