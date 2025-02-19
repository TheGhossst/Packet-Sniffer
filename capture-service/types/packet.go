package types

type PacketData struct {
	Timestamp   string `json:"timestamp"`
	SrcIP       string `json:"src_ip"`
	DstIP       string `json:"dst_ip"`
	Protocol    string `json:"protocol"`
	SrcPort     uint16 `json:"src_port"`
	DstPort     uint16 `json:"dst_port"`
	PacketSize  int    `json:"packet_size"`
	PacketType  string `json:"packet_type"`
	PayloadSize int    `json:"payload_size"`
}
