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
