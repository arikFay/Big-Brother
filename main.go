package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
	"bytes"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
)

const (
	sampleCount    = 12000
	captureTimeout = 5 * time.Second
	deleteInterval = time.Minute
)

type PacketInfo struct {
	SrcIP       string
	DstIP       string
	SrcPort     string
	DstPort     string
	Protocol    string
	VLANID      string
	PacketCount int

	// Ethernet Fields
	EthAddr string
	EthDst  string
	EthSrc  string
	EthType string

	// IP Fields
	IPAddr  string
	IPDst   string
	IPSrc   string
	IPProto string
	IPTTL   string

	// TCP Fields
	TCPPort  string
	TCPFlags string
	TCPSeq   string
	TCPAck   string

	// UDP Fields
	UDPPort string

	// ICMP Fields
	ICMPType string
	ICMPCode string

	// DNS Fields
	DNSQryName  string
	DNSRespName string
	DNSA        string

	// HTTP Fields
	HTTPHost          string
	HTTPRequestMethod string
	HTTPResponseCode  string

	// SSL/TLS Fields
	SSLServerName        string
	SSLRecordContentType string

	// Wireshark-specific Fields
	FrameTime      time.Time
	FrameLength    int
	FrameProtocols []string
}

func main() {
	// Define the interface to capture traffic
	iface := "ens33"

	// Open the interface for capturing packets
	handle, err := pcap.OpenLive(iface, 65536, true, captureTimeout)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	// Create a directory for the pcap and index files
	saveDir := "CAPTURE_" + time.Now().Format("20060102150405")
	err = os.Mkdir(saveDir, 0755)
	if err != nil {
		log.Fatal(err)
	}

	// Set up a signal handler to stop the capture on termination
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packetCount := 0
	fileCount := 1
	var pcapWriter *pcapgo.Writer
	var pcapFile *os.File
	indexFile, err := os.Create(fmt.Sprintf("%s/index.txt", saveDir))
	if err != nil {
		log.Fatal(err)
	}
	defer indexFile.Close()

	// Goroutine to periodically delete pcap files created a minute ago
	go func() {
		for {
			deleteOldPcaps(saveDir)
			time.Sleep(deleteInterval)
		}
	}()

	for packet := range packetSource.Packets() {
		// Extract the relevant fields from the packet
		networkLayer := packet.NetworkLayer()
		transportLayer := packet.TransportLayer()
		dot1qLayer := packet.Layer(layers.LayerTypeDot1Q)
		ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
		ipLayer := packet.Layer(layers.LayerTypeIPv4)
		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		udpLayer := packet.Layer(layers.LayerTypeUDP)
		icmpLayer := packet.Layer(layers.LayerTypeICMPv4)
		dnsLayer := packet.Layer(layers.LayerTypeDNS)
		applicationLayer := packet.ApplicationLayer()
		// sslLayer := packet.Layer(layers.LayerTypeTLS)

		if networkLayer != nil && transportLayer != nil {
			srcIP := networkLayer.NetworkFlow().Src().String()
			dstIP := networkLayer.NetworkFlow().Dst().String()
			srcPort := transportLayer.TransportFlow().Src().String()
			dstPort := transportLayer.TransportFlow().Dst().String()
			protocol := transportLayer.LayerType().String()
			vlanID := ""

			// Check if VLAN information is present
			if dot1qLayer != nil {
				dot1q, _ := dot1qLayer.(*layers.Dot1Q)
				vlanID = fmt.Sprintf("%d", dot1q.VLANIdentifier)
			}

			// Create a new pcap file after every 100 packets
			if packetCount%sampleCount == 0 {
				// Close the previous pcap writer and file
				if pcapWriter != nil {
					// pcapWriter.Flush()
					pcapFile.Close()
				}

				// Create the pcap file name with Ixia Anue timestamp
				pcapFilename := fmt.Sprintf("%s/pcap_%d_%s_%s.pcap", saveDir, fileCount, time.Now().Format("20060102150405"), vlanID)

				// Create the pcap file
				pcapFile, err = os.Create(pcapFilename)
				if err != nil {
					log.Fatal(err)
				}

				// Create the pcap writer
				pcapWriter = pcapgo.NewWriter(pcapFile)
				pcapWriter.WriteFileHeader(65536, layers.LinkTypeEthernet)

				// Write the pcap file name to the index file
				_, err := indexFile.WriteString(fmt.Sprintf("%s\n", pcapFilename))
				if err != nil {
					log.Fatal(err)
				}

				fileCount++
			}

			// Write the packet to the current pcap file
			pcapWriter.WritePacket(packet.Metadata().CaptureInfo, packet.Data())

			// Update the index file with packet information
			packetInfo := PacketInfo{
				SrcIP:       srcIP,
				DstIP:       dstIP,
				SrcPort:     srcPort,
				DstPort:     dstPort,
				Protocol:    protocol,
				VLANID:      vlanID,
				PacketCount: packetCount + 1,
			}

			// Update the additional fields based on the packet layers
			if ethernetLayer != nil {
				ethernet := ethernetLayer.(*layers.Ethernet)
				packetInfo.EthAddr = ethernet.SrcMAC.String()
				packetInfo.EthDst = ethernet.DstMAC.String()
				packetInfo.EthSrc = ethernet.SrcMAC.String()
				packetInfo.EthType = ethernet.EthernetType.String()
			}

			if ipLayer != nil {
				ip := ipLayer.(*layers.IPv4)
				packetInfo.IPAddr = ip.SrcIP.String()
				packetInfo.IPDst = ip.DstIP.String()
				packetInfo.IPSrc = ip.SrcIP.String()
				packetInfo.IPProto = ip.Protocol.String()
				packetInfo.IPTTL = fmt.Sprintf("%d", ip.TTL)
			}

			if tcpLayer != nil {
				tcp := tcpLayer.(*layers.TCP)
				packetInfo.TCPPort = fmt.Sprintf("%d", tcp.SrcPort)

				// Check TCP flags
				var flags []string
				if tcp.FIN {
					flags = append(flags, "FIN")
				}
				if tcp.SYN {
					flags = append(flags, "SYN")
				}
				if tcp.RST {
					flags = append(flags, "RST")
				}
				if tcp.PSH {
					flags = append(flags, "PSH")
				}
				if tcp.ACK {
					flags = append(flags, "ACK")
				}
				if tcp.URG {
					flags = append(flags, "URG")
				}
				if tcp.ECE {
					flags = append(flags, "ECE")
				}
				if tcp.CWR {
					flags = append(flags, "CWR")
				}

				packetInfo.TCPFlags = strings.Join(flags, ", ")
				packetInfo.TCPSeq = fmt.Sprintf("%d", tcp.Seq)
				packetInfo.TCPAck = fmt.Sprintf("%d", tcp.Ack)
			}

			if udpLayer != nil {
				udp := udpLayer.(*layers.UDP)
				packetInfo.UDPPort = fmt.Sprintf("%d", udp.SrcPort)
			}

			if icmpLayer != nil {
				icmp := icmpLayer.(*layers.ICMPv4)
				packetInfo.ICMPType = getICMPTypeString(icmp.TypeCode.Type())
				packetInfo.ICMPCode = getICMPCodeString(icmp.TypeCode.Code())
			}

			if dnsLayer != nil {
				dns := dnsLayer.(*layers.DNS)
				packetInfo.DNSQryName = string(dns.Questions[0].Name)
				// packetInfo.DNSRespName = string(dns.Answers[0].Name)
				// packetInfo.DNSA = dns.Answers[0].IP.String()
			}

			if applicationLayer != nil {
				packetInfo.HTTPHost = extractHTTPHeader(applicationLayer.Payload(), "Host")
				packetInfo.HTTPRequestMethod = extractHTTPHeader(applicationLayer.Payload(), "Method")
				packetInfo.HTTPResponseCode = extractHTTPHeader(applicationLayer.Payload(), "Response-Code")
			}

			// TO-DO SSL Layer

			packetInfo.FrameTime = packet.Metadata().CaptureInfo.Timestamp
			packetInfo.FrameLength = packet.Metadata().Length

			// Get the layer types present in the packet
			var layerTypes []string
			for _, layer := range packet.Layers() {
				layerTypes = append(layerTypes, layer.LayerType().String())
			}

			// Update the index file with packet information
			indexEntry := fmt.Sprintf("Packet Count: %d, Src IP: %s, Dst IP: %s, Src Port: %s, Dst Port: %s, Protocol: %s, VLAN ID: %s\n"+
				"Eth Addr: %s, Eth Dst: %s, Eth Src: %s, Eth Type: %s\n"+
				"IP Addr: %s, IP Dst: %s, IP Src: %s, IP Proto: %s, IP TTL: %s\n"+
				"TCP Port: %s, TCP Flags: %s, TCP Seq: %s, TCP Ack: %s\n"+
				"UDP Port: %s\n"+
				"ICMP Type: %s, ICMP Code: %s\n"+
				"DNS Qry Name: %s, DNS Resp Name: %s, DNS A: %s\n"+
				"HTTP Host: %s, HTTP Request Method: %s, HTTP Response Code: %s\n"+
				"SSL Server Name: %s, SSL Record Content Type: %s\n"+
				"Frame Time: %s, Frame Length: %d, Frame Protocols: %s\n",
				packetInfo.PacketCount, packetInfo.SrcIP, packetInfo.DstIP, packetInfo.SrcPort, packetInfo.DstPort, packetInfo.Protocol, packetInfo.VLANID,
				packetInfo.EthAddr, packetInfo.EthDst, packetInfo.EthSrc, packetInfo.EthType,
				packetInfo.IPAddr, packetInfo.IPDst, packetInfo.IPSrc, packetInfo.IPProto, packetInfo.IPTTL,
				packetInfo.TCPPort, packetInfo.TCPFlags, packetInfo.TCPSeq, packetInfo.TCPAck,
				packetInfo.UDPPort,
				packetInfo.ICMPType, packetInfo.ICMPCode,
				packetInfo.DNSQryName, packetInfo.DNSRespName, packetInfo.DNSA,
				packetInfo.HTTPHost, packetInfo.HTTPRequestMethod, packetInfo.HTTPResponseCode,
				packetInfo.SSLServerName, packetInfo.SSLRecordContentType,
				packetInfo.FrameTime, packetInfo.FrameLength, strings.Join(layerTypes, ", "))

			_, err := indexFile.WriteString(indexEntry)
			if err != nil {
				log.Fatal(err)
			}
			packetCount++
		}

		if packetCount%(sampleCount*fileCount) == 0 {
			fileCount = 1
		}

		if packetCount >= sampleCount*fileCount {
			break
		}
	}

	log.Println("Capture completed.")

	// Wait for termination signal to clean up resources
	<-stop
}

// Function to delete pcap files created a minute ago
func deleteOldPcaps(dir string) {
	files, err := os.ReadDir(dir)
	if err != nil {
		log.Fatal(err)
	}

	currentTime := time.Now()
	for _, file := range files {
		if !file.IsDir() {
			filePath := fmt.Sprintf("%s/%s", dir, file.Name())
			fileInfo, err := os.Stat(filePath)
			if err != nil {
				log.Println(err)
				continue
			}

			fileTime := fileInfo.ModTime()
			elapsedTime := currentTime.Sub(fileTime)
			if elapsedTime > time.Minute {
				err := os.Remove(filePath)
				if err != nil {
					log.Println(err)
				} else {
					log.Printf("Deleted pcap file: %s\n", filePath)
				}
			}
		}
	}
}

// Helper function to extract specific HTTP headers from payload
func extractHTTPHeader(payload []byte, header string) string {
	headerStart := []byte(header + ": ")
	headerEnd := []byte("\r\n")
	startIndex := bytes.Index(payload, headerStart)
	if startIndex == -1 {
		return ""
	}

	startIndex += len(headerStart)
	endIndex := bytes.Index(payload[startIndex:], headerEnd)
	if endIndex == -1 {
		return ""
	}

	return string(payload[startIndex : startIndex+endIndex])
}

// Function to map ICMP type to string
func getICMPTypeString(icmpType uint8) string {
	switch icmpType {
	case layers.ICMPv4TypeEchoRequest:
		return "Echo Request"
	case layers.ICMPv4TypeEchoReply:
		return "Echo Reply"
	case layers.ICMPv4TypeDestinationUnreachable:
		return "Destination Unreachable"
	// Add more cases for other ICMP types if needed
	default:
		return fmt.Sprintf("Unknown (%d)", icmpType)
	}
}

// Function to map ICMP code to string
func getICMPCodeString(icmpCode uint8) string {
	// Add cases for different ICMP codes if needed
	return fmt.Sprintf("%d", icmpCode)
}
