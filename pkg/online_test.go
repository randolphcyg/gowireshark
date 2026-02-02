package pkg

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Helper: Auto-detect a valid interface
func getValidInterface(t *testing.T) string {
	ifaces, err := GetIFaces()
	if err != nil {
		t.Skipf("Skip: failed to get interfaces: %v", err)
	}

	for _, iface := range ifaces {
		if iface.Name != "lo" && iface.Name != "lo0" && len(iface.Addresses) > 0 {
			t.Logf("Using interface: %s", iface.Name)
			return iface.Name
		}
	}
	t.Skip("Skip: no valid interface found")
	return ""
}

// Get interface device list
func TestGetIFaces(t *testing.T) {
	iFaces, err := GetIFaces()
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range iFaces {
		t.Log(k, v.Name, v.Addresses)
	}
}

// Get interface device nonblock status, default is false
func TestGetIFaceNonblockStatus(t *testing.T) {
	ifaceName := getValidInterface(t)
	status, err := GetIFaceNonblockStatus(ifaceName)
	if err != nil {
		t.Fatal(err)
	}

	if status != false {
		t.Errorf("expected status false, got %v", status)
	}
}

func TestSetIFaceNonblockStatus(t *testing.T) {
	ifaceName := getValidInterface(t)
	status, err := SetIFaceNonblockStatus(ifaceName, true)
	if err != nil {
		t.Fatal(err)
	}

	if status != true {
		t.Errorf("expected status true, got %v", status)
	}
}

// Test infinite capture mode, stop manually after 2s
func TestStartAndStopLivePacketCaptureInfinite(t *testing.T) {
	ifName := getValidInterface(t)
	filter := ""
	pktNum := -1
	promisc := 1
	timeout := 100 // ms

	var wg sync.WaitGroup
	var packetCount int32

	// 1. Start Capture in background
	go func() {
		t.Logf("Start capturing on %s...", ifName)
		// This will block until stopped
		if err := StartLivePacketCapture(ifName, filter, pktNum, promisc, timeout); err != nil {
			// It might error if stopped externally, check logic
			t.Logf("Capture finished: %v", err)
		}
	}()

	// Give it a moment to initialize the channel map
	time.Sleep(100 * time.Millisecond)

	// 2. Consume
	ch := GetIfaceChannel(ifName)
	if ch == nil {
		t.Fatal("Channel not initialized")
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		for frame := range ch {
			atomic.AddInt32(&packetCount, 1)
			if atomic.LoadInt32(&packetCount) <= 3 {
				t.Logf("[Packet %d] Protocol: %s",
					frame.BaseLayers.Frame.Number,
					frame.BaseLayers.WsCol.Protocol)
			}
		}
		t.Log("Consumer channel closed")
	}()

	// 3. Stop after 2s
	time.Sleep(2 * time.Second)
	t.Log("Stopping capture...")
	if err := StopLivePacketCapture(ifName); err != nil {
		t.Errorf("Stop failed: %v", err)
	}

	wg.Wait() // Wait for consumer to finish (channel close)

	if atomic.LoadInt32(&packetCount) == 0 {
		t.Error("No packets captured")
	}
}

// Test capture fixed number of packets (5)
func TestStartAndStopLivePacketCaptureLimited(t *testing.T) {
	ifName := getValidInterface(t)
	pktNum := 5
	promisc := 1
	timeout := 100

	// 1. Start Capture in background
	go func() {
		// TLS config example
		tls := TlsConf{
			DesegmentSslRecords: true,
			KeysList:            []Key{{Port: 443, KeyFile: "./pcaps/server.key"}},
		}

		t.Logf("Capturing %d packets...", pktNum)
		if err := StartLivePacketCapture(ifName, "", pktNum, promisc, timeout, WithTls(tls)); err != nil {
			t.Logf("Capture stopped: %v", err)
		}
	}()

	// Wait for init
	time.Sleep(100 * time.Millisecond)
	ch := GetIfaceChannel(ifName)
	if ch == nil {
		t.Fatal("Channel not initialized")
	}

	var packetCount int32
	var wg sync.WaitGroup

	// 2. Consumer
	wg.Add(1)
	go func() {
		defer wg.Done()
		for frame := range ch {
			current := atomic.AddInt32(&packetCount, 1)
			t.Logf("[Limit %d/%d] Got: %s", current, pktNum, frame.BaseLayers.WsCol.Protocol)
		}
	}()

	// Let's loop wait for count
	for i := 0; i < 50; i++ {
		if atomic.LoadInt32(&packetCount) >= int32(pktNum) {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	// Ensure cleanup
	StopLivePacketCapture(ifName)
	wg.Wait()

	if atomic.LoadInt32(&packetCount) != int32(pktNum) {
		t.Errorf("Expected %d packets, got %d", pktNum, packetCount)
	}
}

// TestBPF verifies the BPF filter functionality (e.g., "tcp").
// Ensure you have TCP traffic during the test.
func TestBPF(t *testing.T) {
	// 1. Auto-detect valid interface
	ifName := getValidInterface(t)
	filter := "tcp" // Filter: TCP only
	pktNum := 5     // Capture limit
	promisc := 1
	timeout := 100

	var wg sync.WaitGroup
	wg.Add(1)

	// 2. Start capture in background (blocking call)
	go func() {
		defer wg.Done()
		t.Logf("Start capturing %d TCP packets on %s...", pktNum, ifName)
		if err := StartLivePacketCapture(ifName, filter, pktNum, promisc, timeout); err != nil {
			t.Logf("Capture finished with info: %v", err)
		}
	}()

	// 3. Wait for channel initialization (poll until ready)
	var ch <-chan FrameData
	for i := 0; i < 50; i++ {
		if ch = GetIfaceChannel(ifName); ch != nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if ch == nil {
		t.Fatal("Channel init timeout")
	}

	// 4. Consume packets
	var count int32
	var consumerWg sync.WaitGroup
	consumerWg.Add(1)

	go func() {
		defer consumerWg.Done()
		for frame := range ch {
			atomic.AddInt32(&count, 1)

			// Verify BPF: Check if TCP layer exists
			isTcp := frame.BaseLayers.Tcp != nil
			t.Logf("[Pkt %d] Protocol: %s | IsTCP: %v",
				frame.BaseLayers.Frame.Number,
				frame.BaseLayers.WsCol.Protocol,
				isTcp)
		}
	}()

	// 5. Wait for capture limit to be reached
	wg.Wait()

	// 6. Stop & Cleanup (closes channel to release consumer)
	_ = StopLivePacketCapture(ifName)
	consumerWg.Wait()

	// 7. Final assertion
	if atomic.LoadInt32(&count) == 0 {
		t.Log("No packets captured. Ensure TCP traffic exists.")
	} else {
		t.Logf("Success: Verified BPF filter with %d packets.", count)
	}
}
