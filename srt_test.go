package gowireshark

import (
	"testing"

	"github.com/randolphcyg/gowireshark/internal/testfixture"
)

func TestSRTSMB_DoesNotCrash(t *testing.T) {
	pcap := testfixture.Pcap(t)

	srt, err := ServiceResponseTimes(pcap, "smb")
	if err != nil {
		t.Fatalf("ServiceResponseTimes smb: %v", err)
	}
	if srt == nil {
		t.Fatal("expected non-nil SRT result")
	}
	t.Logf("found %d SMB SRT entries", len(srt))
	for _, e := range srt {
		if e.Protocol != "smb" {
			t.Fatalf("expected protocol smb, got %q", e.Protocol)
		}
		if e.Procedure == "" {
			t.Fatalf("expected non-empty procedure: %#v", e)
		}
		if e.Calls == 0 {
			t.Fatalf("expected non-zero calls: %#v", e)
		}
		t.Logf("  procedure=%q calls=%d min=%.6f max=%.6f avg=%.6f total=%.6f",
			e.Procedure, e.Calls, e.Min, e.Max, e.Avg, e.Total)
	}
}

func TestSRTSMB2_DoesNotCrash(t *testing.T) {
	pcap := testfixture.Pcap(t)

	srt, err := ServiceResponseTimes(pcap, "smb2")
	if err != nil {
		t.Fatalf("ServiceResponseTimes smb2: %v", err)
	}
	if srt == nil {
		t.Fatal("expected non-nil SRT result")
	}
	t.Logf("found %d SMB2 SRT entries", len(srt))
}

func TestSRTWithFilter(t *testing.T) {
	pcap := testfixture.Pcap(t)

	all, err := ServiceResponseTimes(pcap, "smb")
	if err != nil {
		t.Fatalf("ServiceResponseTimes all: %v", err)
	}

	filtered, err := ServiceResponseTimes(pcap, "smb", WithDisplayFilter("frame.number == 1"))
	if err != nil {
		t.Fatalf("ServiceResponseTimes filtered: %v", err)
	}

	if len(filtered) > len(all) {
		t.Fatalf("filtered SRT (%d) should not exceed unfiltered (%d)", len(filtered), len(all))
	}
}

func TestSessionSRTMatchesFreeFunction(t *testing.T) {
	pcap := testfixture.Pcap(t)

	freeSRT, err := ServiceResponseTimes(pcap, "smb", WithDisplayFilter("frame.number <= 5"))
	if err != nil {
		t.Fatalf("ServiceResponseTimes: %v", err)
	}

	s, err := OpenSession(pcap)
	if err != nil {
		t.Fatalf("OpenSession: %v", err)
	}
	defer s.Close()

	sessionSRT, err := s.ServiceResponseTimes("smb", Query{Filter: "frame.number <= 5"})
	if err != nil {
		t.Fatalf("Session.ServiceResponseTimes: %v", err)
	}
	if len(sessionSRT) != len(freeSRT) {
		t.Fatalf("SRT count mismatch: session=%d free=%d", len(sessionSRT), len(freeSRT))
	}
}

func TestSRTUnsupportedProtocol(t *testing.T) {
	pcap := testfixture.Pcap(t)

	_, err := ServiceResponseTimes(pcap, "dns")
	if err == nil {
		t.Fatal("expected error for unsupported SRT protocol")
	}
}

func TestSRTInvalidFilter(t *testing.T) {
	pcap := testfixture.Pcap(t)

	_, err := ServiceResponseTimes(pcap, "smb", WithDisplayFilter("bogus_field == 42"))
	if err == nil {
		t.Fatal("expected error for invalid filter")
	}
}

func TestSRTSessionClosed(t *testing.T) {
	pcap := testfixture.Pcap(t)

	s, err := OpenSession(pcap)
	if err != nil {
		t.Fatalf("OpenSession: %v", err)
	}
	s.Close()

	_, err = s.ServiceResponseTimes("smb", Query{})
	if err == nil {
		t.Fatal("expected error for closed session")
	}
}