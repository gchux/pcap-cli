package pcap

import (
	"context"
	"fmt"
	"net"
	"regexp"
	"sync/atomic"
	"time"

	"github.com/gchux/pcap-cli/pkg/transformer"
	"github.com/google/gopacket/pcap"
	"github.com/wissance/stringFormatter"
)

type (
	PcapFilterMode uint8

	PcapFilter struct {
		Raw *string
	}

	PcapFilterProvider interface {
		fmt.Stringer
		Get(context.Context) (*string, bool)
		Apply(context.Context, *string, PcapFilterMode) *string
	}

	PcapConfig struct {
		Debug     bool
		Promisc   bool
		Iface     string
		Snaplen   int
		TsType    string
		Format    string
		Filter    string
		Output    string
		Interval  int
		Extension string
		Ordered   bool
		ConnTrack bool
		Device    *PcapDevice
		Filters   []PcapFilterProvider
	}

	PcapEngine interface {
		Start(context.Context, []PcapWriter, <-chan *time.Duration) error
		IsActive() bool
	}

	PcapDevice struct {
		NetInterface *net.Interface
		pcap.Interface
	}

	Pcap struct {
		config         *PcapConfig
		isActive       *atomic.Bool
		activeHandle   *pcap.Handle
		inactiveHandle *pcap.InactiveHandle
		fn             transformer.IPcapTransformer
	}

	Tcpdump struct {
		config   *PcapConfig
		isActive *atomic.Bool
		tcpdump  string
	}
)

const (
	PCAP_FILTER_MODE_AND PcapFilterMode = iota
	PCAP_FILTER_MODE_OR
)

const (
	PcapContextID      = transformer.ContextID
	PcapContextLogName = transformer.ContextLogName
)

func providePcapFilter(
	ctx context.Context,
	filter *string,
	providers []PcapFilterProvider,
) *string {
	select {
	case <-ctx.Done():
		return filter
	default:
	}
	pcapFilter := stringFormatter.Format("({0})", *filter)
	for _, provider := range providers {
		pcapFilter = *provider.Apply(ctx, &pcapFilter, PCAP_FILTER_MODE_AND)
	}
	return &pcapFilter
}

func findAllDevs(compare func(*string) bool) ([]*PcapDevice, error) {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		return nil, err
	}

	var devs []*PcapDevice

	for _, device := range devices {
		if compare(&device.Name) {
			iface, err := net.InterfaceByName(device.Name)
			if err != nil {
				continue
			}
			devs = append(devs, &PcapDevice{iface, device})
		}
	}

	return devs, nil
}

func FindDevicesByRegex(exp *regexp.Regexp) ([]*PcapDevice, error) {
	compare := func(deviceName *string) bool {
		return exp.MatchString(*deviceName)
	}
	return findAllDevs(compare)
}

func FindDevicesByName(deviceName *string) ([]*PcapDevice, error) {
	name := *deviceName
	compare := func(deviceName *string) bool {
		return name == *deviceName
	}
	return findAllDevs(compare)
}
