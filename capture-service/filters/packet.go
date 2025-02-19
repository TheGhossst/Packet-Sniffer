package filters

import "ids/capture-service/types"

type PacketFilter struct {
	Ports     []uint16
	Protocols []string
	IPs       []string
}

func NewPacketFilter() *PacketFilter {
	return &PacketFilter{
		Ports:     []uint16{80, 443, 22, 53},
		Protocols: []string{"TCP", "UDP", "ICMP"},
		IPs:       []string{},
	}
}

func (f *PacketFilter) ShouldProcess(packet types.PacketData) bool {
	// Skip if port is not in monitored ports
	if len(f.Ports) > 0 {
		portMatch := false
		for _, port := range f.Ports {
			if packet.SrcPort == port || packet.DstPort == port {
				portMatch = true
				break
			}
		}
		if !portMatch {
			return false
		}
	}
	return true
}
