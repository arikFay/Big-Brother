package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
)

const (
	sampleCount    = 100
	captureTimeout = 5 * time.Second
)

type PacketInfo struct {
	SrcIP        string
	DstIP        string
	SrcPort      string
	DstPort      string
	Protocol     string
	PacketCount  int
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
	saveDir := "ixia_anue_" + time.Now().Format("20060102150405")
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

	for packet := range packetSource.Packets() {
		// Extract the relevant fields from the packet
		networkLayer := packet.NetworkLayer()
		transportLayer := packet.TransportLayer()

		if networkLayer != nil && transportLayer != nil {
			srcIP := networkLayer.NetworkFlow().Src().String()
			dstIP := networkLayer.NetworkFlow().Dst().String()
			srcPort := transportLayer.TransportFlow().Src().String()
			dstPort := transportLayer.TransportFlow().Dst().String()
			protocol := transportLayer.LayerType().String()

			// Create a new pcap file after every 100 packets
			if packetCount%sampleCount == 0 {
				// Close the previous pcap writer and file
				if pcapWriter != nil {
					// pcapWriter.Flush()
					pcapFile.Close()
				}

				// Create the pcap file
				pcapFilename := fmt.Sprintf("%s/pcap_%d_%s.pcap", saveDir, fileCount, time.Now().Format("20060102150405"))
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

			// Update the index file with 5-tuple information
			indexEntry := fmt.Sprintf("Packet Count: %d, Src IP: %s, Dst IP: %s, Src Port: %s, Dst Port: %s, Protocol: %s\n",
				packetCount+1, srcIP, dstIP, srcPort, dstPort, protocol)

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
