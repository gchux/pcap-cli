package pcap

import (
	"context"
	"net"
	"regexp"
	"sync/atomic"

	"github.com/gchux/pcap-cli/pkg/transformer"
	"github.com/google/gopacket/pcap"
	gpcap "github.com/google/gopacket/pcap"
)

type (
	PcapConfig struct {
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
		Device    *PcapDevice
	}

	PcapEngine interface {
		Start(context.Context, []PcapWriter) error
		IsActive() bool
	}

	PcapDevice struct {
		netInterface *net.Interface
		pcap.Interface
	}

	Pcap struct {
		config         *PcapConfig
		isActive       *atomic.Bool
		activeHandle   *gpcap.Handle
		inactiveHandle *gpcap.InactiveHandle
		fn             transformer.IPcapTransformer
	}

	Tcpdump struct {
		config   *PcapConfig
		isActive *atomic.Bool
		tcpdump  string
	}
)

const (
	PcapContextID      = transformer.ContextID
	PcapContextLogName = transformer.ContextLogName
)

func findAllDevs(compare func(*string) bool) ([]*PcapDevice, error) {
	devices, err := gpcap.FindAllDevs()
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
