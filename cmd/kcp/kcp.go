package main

import (
	"crypto/sha1"
	"fmt"
	"log"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/spf13/cobra"
	"github.com/xtaci/kcp-go/v5"
	"golang.org/x/crypto/pbkdf2"
)

type Kcp struct {
	filename string

	udpSession *kcp.UDPSession
}

// Segment defines a KCP segment
type Segment struct {
	Conv     uint32 `json:"conv"`     // 会话 ID
	Cmd      uint8  `json:"cmd"`      // 命令类型
	Frg      uint8  `json:"frg"`      // 分片数量
	Wnd      uint16 `json:"wnd"`      // 窗口大小
	Ts       uint32 `json:"ts"`       // 时间戳
	SN       uint32 `json:"sn"`       // 序列号
	Una      uint32 `json:"una"`      // 未确认序号
	Rto      uint32 `json:"rto"`      // 重传超时
	Xmit     uint32 `json:"xmit"`     // 传输次数
	Resendts uint32 `json:"resendts"` // 重传时间戳
	Fastack  uint32 `json:"fastack"`  // 快速确认数
	Acked    uint32 `json:"acked"`    // 是否已确认
	Len      uint32 `json:"len"`      // 数据长度
	Data     []byte `json:"data"`     // 载荷数据
}

func New() *Kcp {
	k := Kcp{}

	key := pbkdf2.Key([]byte("demo pass"), []byte("demo salt"), 1024, 32, sha1.New)
	block, _ := kcp.NewAESBlockCrypt(key)
	k.udpSession = kcp.NewEmptyUdpSession(block)

	return &k
}

func (k *Kcp) ParseFlags(cmd *cobra.Command) {
	cmd.Flags().StringVarP(&k.filename, "file", "f", "", "pcap file to read from")

}

func (k *Kcp) GetPcapFileName() string {
	return k.filename
}

func (k *Kcp) Run() error {
	// 1. 打开 pcap 文件
	// 如果文件不存在或格式错误，这里会报错
	handle, err := pcap.OpenOffline(k.filename)
	if err != nil {
		log.Fatalf("无法打开 pcap 文件 %s: %v", k.filename, err)
		return err
	}
	defer handle.Close()

	fmt.Printf("开始解析文件：%s\n", k.filename)
	fmt.Printf("链路层类型：%v (%d)\n", handle.LinkType(), int(handle.LinkType()))
	fmt.Println("------------------------------------------------------------")
	// 创建数据包源
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	// 2. 遍历每一个数据包
	for packet := range packetSource.Packets() {

		// A nil packet indicates the end of a pcap file.
		if packet == nil {
			fmt.Println("文件解析完毕")
			return nil
		}

		if packet.LinkLayer() == nil || packet.NetworkLayer() == nil || packet.TransportLayer() == nil || packet.TransportLayer().LayerType() != layers.LayerTypeUDP {
			log.Println("not udp packet continue", packet)
			continue
		}

		// 提取具体的 IP 信息
		var srcIP, dstIP net.IP
		srcIP = packet.NetworkLayer().NetworkFlow().Src().Raw()
		dstIP = packet.NetworkLayer().NetworkFlow().Dst().Raw()

		// 3. 解析 UDP 层
		udp, ok := packet.TransportLayer().(*layers.UDP)
		if !ok {
			log.Println("get udp data failed")
			continue
		}

		// 5. 获取 UDP 载荷 (Payload)
		payload := udp.LayerPayload()

		k.udpSession.PcapPacketInput(payload)

		// 打印详细信息
		fmt.Printf("[%s] %s:%d -> %s:%d \n",
			packet.Metadata().Timestamp.Format("15:04:05.000"),
			srcIP, udp.SrcPort,
			dstIP, udp.DstPort,
		)
	}

	return nil
}
