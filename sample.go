package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/google/gopacket/layers"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
)

const (
	sampleCount    = 200
	captureTimeout = 5 * time.Second
)

func main() {
	// Define the interface to capture traffic
	iface := "ens33"

	// Open the interface for capturing packets
	handle, err := pcap.OpenLive(iface, 65536, true, captureTimeout)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	// Create the pcap file with a timestamp from Ixia Anue
	timestamp := time.Now().Format("20060102150405")
	pcapFilename := fmt.Sprintf("sample_%s.pcap", timestamp)
	pcapFile, err := os.Create(pcapFilename)
	if err != nil {
		log.Fatal(err)
	}
	defer pcapFile.Close()

	// Create the pcap writer
	pcapWriter := pcapgo.NewWriter(pcapFile)
	pcapWriter.WriteFileHeader(65536, layers.LinkTypeEthernet)

	// Create the index file with a timestamp from Ixia Anue
	indexFilename := fmt.Sprintf("index_%s.txt", timestamp)
	indexFile, err := os.Create(indexFilename)
	if err != nil {
		log.Fatal(err)
	}
	defer indexFile.Close()

	// Write the index file header
	indexFile.WriteString("Timestamp,Source IP,Destination IP,Source Port,Destination Port,Protocol\n")

	// Set up a signal handler to stop the capture on termination
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packetCount := 0

	// Capture packets until reaching the desired sample count or receiving a termination signal
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

			// Write the packet to the pcap file
			pcapWriter.WritePacket(packet.Metadata().CaptureInfo, packet.Data())

			// Write the index entry to the index file
			indexEntry := fmt.Sprintf("%s,%s,%s,%s,%s,%s\n",
				packet.Metadata().Timestamp.Format(time.RFC3339),
				srcIP, dstIP, srcPort, dstPort, protocol)
			indexFile.WriteString(indexEntry)

			packetCount++

			if packetCount == sampleCount {
				break
			}
		}
	}

	log.Println("Capture completed.")

	// Wait for termination signal to clean up resources
	<-stop
}
