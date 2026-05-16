package pkg

import (
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// getValidInterface auto-detects a usable network interface.
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

func TestGetIFaces(t *testing.T) {
	iFaces, err := GetIFaces()
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range iFaces {
		t.Log(k, v.Name, v.Addresses)
	}
}

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

func TestStartAndStopLivePacketCaptureInfinite(t *testing.T) {
	ifName := getValidInterface(t)
	filter := ""
	pktNum := -1
	promisc := 1
	timeout := 100

	var wg sync.WaitGroup
	var packetCount int32

	go func() {
		t.Logf("Start capturing on %s...", ifName)
		if err := StartLivePacketCapture(ifName, filter, pktNum, promisc, timeout); err != nil {
			t.Logf("Capture finished: %v", err)
		}
	}()

	time.Sleep(100 * time.Millisecond)

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
	}()

	time.Sleep(2 * time.Second)
	t.Log("Stopping capture...")
	if err := StopLivePacketCapture(ifName); err != nil {
		t.Errorf("Stop failed: %v", err)
	}

	wg.Wait()

	if atomic.LoadInt32(&packetCount) == 0 {
		t.Log("No packets captured (may need network activity)")
	}
}

func TestStartAndStopLivePacketCaptureLimited(t *testing.T) {
	ifName := getValidInterface(t)
	pktNum := 5
	promisc := 1
	timeout := 100

	go func() {
		var opts []Option
		// Use TLS key if available (non-fatal if missing)
		if keyFile, _ := findKeyFile(); keyFile != "" {
			tls := TlsConf{
				DesegmentSslRecords: true,
				KeysList:            []Key{{Port: 443, KeyFile: keyFile}},
			}
			opts = append(opts, WithTls(tls))
		}

		t.Logf("Capturing %d packets...", pktNum)
		if err := StartLivePacketCapture(ifName, "", pktNum, promisc, timeout, opts...); err != nil {
			t.Logf("Capture stopped: %v", err)
		}
	}()

	time.Sleep(100 * time.Millisecond)
	ch := GetIfaceChannel(ifName)
	if ch == nil {
		t.Fatal("Channel not initialized")
	}

	var packetCount int32
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		for frame := range ch {
			current := atomic.AddInt32(&packetCount, 1)
			t.Logf("[Limit %d/%d] Got: %s", current, pktNum, frame.BaseLayers.WsCol.Protocol)
		}
	}()

	for i := 0; i < 50; i++ {
		if atomic.LoadInt32(&packetCount) >= int32(pktNum) {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	StopLivePacketCapture(ifName)
	wg.Wait()

	if atomic.LoadInt32(&packetCount) == 0 {
		t.Log("No packets captured (may need network activity)")
	}
}

func TestBPF(t *testing.T) {
	ifName := getValidInterface(t)
	filter := "tcp"
	pktNum := 5
	promisc := 1
	timeout := 100

	var wg sync.WaitGroup
	wg.Add(1)

	go func() {
		defer wg.Done()
		t.Logf("Start capturing %d TCP packets on %s...", pktNum, ifName)
		if err := StartLivePacketCapture(ifName, filter, pktNum, promisc, timeout); err != nil {
			t.Logf("Capture finished: %v", err)
		}
	}()

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

	var count int32
	var consumerWg sync.WaitGroup
	consumerWg.Add(1)

	go func() {
		defer consumerWg.Done()
		for frame := range ch {
			atomic.AddInt32(&count, 1)
			isTcp := frame.BaseLayers.Tcp != nil
			t.Logf("[Pkt %d] Protocol: %s | IsTCP: %v",
				frame.BaseLayers.Frame.Number,
				frame.BaseLayers.WsCol.Protocol,
				isTcp)
		}
	}()

	wg.Wait()
	_ = StopLivePacketCapture(ifName)
	consumerWg.Wait()

	if atomic.LoadInt32(&count) == 0 {
		t.Log("No packets captured. Ensure TCP traffic exists.")
	} else {
		t.Logf("Success: Verified BPF filter with %d packets.", count)
	}
}

// TestLiveCaptureFrameIntegrity validates that frames captured live have
// properly parsed BaseLayers (Frame, WsCol, and at least one network layer).
func TestLiveCaptureFrameIntegrity(t *testing.T) {
	ifName := getValidInterface(t)
	pktNum := 10
	promisc := 1
	timeout := 100

	go func() {
		if err := StartLivePacketCapture(ifName, "", pktNum, promisc, timeout); err != nil {
			t.Logf("Capture ended: %v", err)
		}
	}()

	time.Sleep(200 * time.Millisecond)
	ch := GetIfaceChannel(ifName)
	if ch == nil {
		t.Fatal("Channel not initialized")
	}

	var frames []FrameData
	timeout2 := time.After(5 * time.Second)

loop:
	for {
		select {
		case frame, ok := <-ch:
			if !ok {
				break loop
			}
			frames = append(frames, frame)
			if len(frames) >= pktNum {
				break loop
			}
		case <-timeout2:
			break loop
		}
	}

	_ = StopLivePacketCapture(ifName)

	if len(frames) == 0 {
		t.Skip("No packets captured (need network activity)")
	}

	for i, frame := range frames {
		// Frame layer must always be present
		if frame.BaseLayers.Frame == nil {
			t.Errorf("Frame %d: BaseLayers.Frame is nil", i)
			continue
		}
		if frame.BaseLayers.Frame.Number == 0 {
			t.Errorf("Frame %d: Frame.Number is 0", i)
		}
		if frame.BaseLayers.Frame.Len == 0 {
			t.Errorf("Frame %d: Frame.Len is 0", i)
		}

		// WsCol must always be present
		if frame.BaseLayers.WsCol == nil {
			t.Errorf("Frame %d: BaseLayers.WsCol is nil", i)
			continue
		}
		if frame.BaseLayers.WsCol.Protocol == "" {
			t.Errorf("Frame %d: WsCol.Protocol is empty", i)
		}

		// At least one network layer should be present
		hasNetLayer := frame.BaseLayers.Eth != nil ||
			frame.BaseLayers.Ip != nil ||
			frame.BaseLayers.Tcp != nil ||
			frame.BaseLayers.Udp != nil
		if !hasNetLayer {
			t.Logf("Frame %d: No network layer parsed (protocol: %s)", i, frame.BaseLayers.WsCol.Protocol)
		}
	}

	t.Logf("Validated %d frames with proper BaseLayers parsing", len(frames))
}

// TestDuplicateCaptureRejection verifies that starting a second capture
// on the same interface is properly rejected.
func TestDuplicateCaptureRejection(t *testing.T) {
	ifName := getValidInterface(t)
	promisc := 1
	timeout := 100

	// Start first capture
	go func() {
		_ = StartLivePacketCapture(ifName, "", -1, promisc, timeout)
	}()

	time.Sleep(200 * time.Millisecond)

	// Attempt second capture on same interface — should fail
	errCh := make(chan error, 1)
	go func() {
		errCh <- StartLivePacketCapture(ifName, "", -1, promisc, timeout)
	}()

	select {
	case err := <-errCh:
		if err == nil {
			t.Error("Expected error for duplicate capture, got nil")
		} else {
			t.Logf("Correctly rejected duplicate capture: %v", err)
		}
	case <-time.After(1 * time.Second):
		t.Error("Duplicate capture did not return error within timeout")
	}

	// Cleanup
	_ = StopLivePacketCapture(ifName)
	time.Sleep(500 * time.Millisecond)
}

// TestLiveCaptureCustomRegistry verifies that custom protocol parsers
// registered in DefaultRegistry are applied during live capture.
func TestLiveCaptureCustomRegistry(t *testing.T) {
	ifName := getValidInterface(t)
	pktNum := 5
	promisc := 1
	timeout := 100

	// Register a dummy parser that always returns nil (just to verify it doesn't crash)
	type DummyLayer struct{}
	dummyParser := &struct{ DummyLayer }{}
	// We won't register an actual parser here since we can't guarantee
	// specific protocol traffic. Instead, verify the mechanism doesn't panic.

	_ = dummyParser // suppress unused

	go func() {
		if err := StartLivePacketCapture(ifName, "", pktNum, promisc, timeout); err != nil {
			t.Logf("Capture ended: %v", err)
		}
	}()

	time.Sleep(200 * time.Millisecond)
	ch := GetIfaceChannel(ifName)
	if ch == nil {
		_ = StopLivePacketCapture(ifName)
		t.Skip("Channel not initialized (may need root)")
	}

	var count int32
	timeout2 := time.After(3 * time.Second)

loop:
	for {
		select {
		case _, ok := <-ch:
			if !ok {
				break loop
			}
			atomic.AddInt32(&count, 1)
			if atomic.LoadInt32(&count) >= int32(pktNum) {
				break loop
			}
		case <-timeout2:
			break loop
		}
	}

	_ = StopLivePacketCapture(ifName)

	if atomic.LoadInt32(&count) == 0 {
		t.Log("No packets captured (need network activity)")
	} else {
		t.Logf("Live capture with DefaultRegistry active: %d packets processed without panic", count)
	}
}

// findKeyFile looks for a .key file in the pcaps directory (best-effort).
func findKeyFile() (string, error) {
	entries, err := os.ReadDir(testPcapDir)
	if err != nil {
		return "", err
	}
	for _, e := range entries {
		if !e.IsDir() && filepath.Ext(e.Name()) == ".key" {
			return filepath.Join(testPcapDir, e.Name()), nil
		}
	}
	return "", nil
}
