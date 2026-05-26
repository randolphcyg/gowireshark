package gowireshark

import (
	"testing"

	"github.com/randolphcyg/gowireshark/internal/testfixture"
)

func TestTapConversationsTCP_DoesNotCrash(t *testing.T) {
	pcap := testfixture.Pcap(t)

	convs, err := TapConversations(pcap, "tcp")
	if err != nil {
		t.Fatalf("TapConversations tcp: %v", err)
	}
	if convs == nil {
		t.Fatal("expected non-nil conversations")
	}
}

func TestTapConversationsUDP_DoesNotCrash(t *testing.T) {
	pcap := testfixture.Pcap(t)

	convs, err := TapConversations(pcap, "udp")
	if err != nil {
		t.Fatalf("TapConversations udp: %v", err)
	}
	if convs == nil {
		t.Fatal("expected non-nil conversations")
	}
}

func TestTapConversationsIP_DoesNotCrash(t *testing.T) {
	pcap := testfixture.Pcap(t)

	convs, err := TapConversations(pcap, "ip")
	if err != nil {
		t.Fatalf("TapConversations ip: %v", err)
	}
	if convs == nil {
		t.Fatal("expected non-nil conversations")
	}
}

func TestTapConversationsETH_DoesNotCrash(t *testing.T) {
	pcap := testfixture.Pcap(t)

	convs, err := TapConversations(pcap, "eth")
	if err != nil {
		t.Fatalf("TapConversations eth: %v", err)
	}
	if convs == nil {
		t.Fatal("expected non-nil conversations")
	}
}

func TestTapConversationsWithFilter(t *testing.T) {
	pcap := testfixture.Pcap(t)

	allTCP, err := TapConversations(pcap, "tcp")
	if err != nil {
		t.Fatalf("TapConversations all: %v", err)
	}

	filtered, err := TapConversations(pcap, "tcp", WithDisplayFilter("frame.number == 1"))
	if err != nil {
		t.Fatalf("TapConversations filtered: %v", err)
	}

	if len(filtered) > len(allTCP) {
		t.Fatalf("filtered conversations (%d) should not exceed unfiltered (%d)", len(filtered), len(allTCP))
	}
}

func TestTapEndpointsTCP_DoesNotCrash(t *testing.T) {
	pcap := testfixture.Pcap(t)

	eps, err := TapEndpoints(pcap, "tcp")
	if err != nil {
		t.Fatalf("TapEndpoints tcp: %v", err)
	}
	if eps == nil {
		t.Fatal("expected non-nil endpoints")
	}
}

func TestTapEndpointsWithFilter(t *testing.T) {
	pcap := testfixture.Pcap(t)

	allTCP, err := TapEndpoints(pcap, "tcp")
	if err != nil {
		t.Fatalf("TapEndpoints all: %v", err)
	}

	filtered, err := TapEndpoints(pcap, "tcp", WithDisplayFilter("frame.number == 1"))
	if err != nil {
		t.Fatalf("TapEndpoints filtered: %v", err)
	}

	if len(filtered) > len(allTCP) {
		t.Fatalf("filtered endpoints (%d) should not exceed unfiltered (%d)", len(filtered), len(allTCP))
	}
}

func TestSessionTapConversationsMatchesFreeFunction(t *testing.T) {
	pcap := testfixture.Pcap(t)

	freeConvs, err := TapConversations(pcap, "tcp", WithDisplayFilter("frame.number <= 5"))
	if err != nil {
		t.Fatalf("TapConversations: %v", err)
	}

	s, err := openSession(pcap)
	if err != nil {
		t.Fatalf("OpenSession: %v", err)
	}
	defer s.Close()

	sessionConvs, err := s.TapConversations("tcp", Query{Filter: "frame.number <= 5"})
	if err != nil {
		t.Fatalf("Session.TapConversations: %v", err)
	}
	if len(sessionConvs) != len(freeConvs) {
		t.Fatalf("conversation count mismatch: session=%d free=%d", len(sessionConvs), len(freeConvs))
	}
}

func TestSessionTapEndpointsMatchesFreeFunction(t *testing.T) {
	pcap := testfixture.Pcap(t)

	freeEps, err := TapEndpoints(pcap, "tcp", WithDisplayFilter("frame.number <= 5"))
	if err != nil {
		t.Fatalf("TapEndpoints: %v", err)
	}

	s, err := openSession(pcap)
	if err != nil {
		t.Fatalf("OpenSession: %v", err)
	}
	defer s.Close()

	sessionEps, err := s.TapEndpoints("tcp", Query{Filter: "frame.number <= 5"})
	if err != nil {
		t.Fatalf("Session.TapEndpoints: %v", err)
	}
	if len(sessionEps) != len(freeEps) {
		t.Fatalf("endpoint count mismatch: session=%d free=%d", len(sessionEps), len(freeEps))
	}
}

func TestTapConversationsUnsupportedType(t *testing.T) {
	pcap := testfixture.Pcap(t)

	_, err := TapConversations(pcap, "sctp")
	if err == nil {
		t.Fatal("expected error for unsupported conversation type")
	}
}

func TestTapEndpointsUnsupportedType(t *testing.T) {
	pcap := testfixture.Pcap(t)

	_, err := TapEndpoints(pcap, "arp")
	if err == nil {
		t.Fatal("expected error for unsupported endpoint type")
	}
}

func TestTapConversationsInvalidFilter(t *testing.T) {
	pcap := testfixture.Pcap(t)

	_, err := TapConversations(pcap, "tcp", WithDisplayFilter("bogus_field == 42"))
	if err == nil {
		t.Fatal("expected error for invalid filter")
	}
}

func TestProtocolHierarchy_DoesNotCrash(t *testing.T) {
	pcap := testfixture.Pcap(t)

	entries, err := ProtocolHierarchy(pcap)
	if err != nil {
		t.Fatalf("ProtocolHierarchy: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("expected at least one protocol hierarchy entry")
	}
	for _, e := range entries {
		if e.Protocol == "" {
			t.Fatalf("empty protocol name in entry: %+v", e)
		}
		if e.Packets == 0 {
			t.Fatalf("zero packets for protocol %q", e.Protocol)
		}
	}
	t.Logf("found %d protocol entries", len(entries))
}

func TestProtocolHierarchy_WithFilter(t *testing.T) {
	pcap := testfixture.Pcap(t)

	all, err := ProtocolHierarchy(pcap)
	if err != nil {
		t.Fatalf("ProtocolHierarchy all: %v", err)
	}
	filtered, err := ProtocolHierarchy(pcap, WithDisplayFilter("frame.number == 1"))
	if err != nil {
		t.Fatalf("ProtocolHierarchy filtered: %v", err)
	}
	if len(filtered) == 0 {
		t.Fatal("expected at least one entry with filter frame.number==1")
	}
	for _, fe := range filtered {
		found := false
		for _, ae := range all {
			if ae.Protocol == fe.Protocol {
				if fe.Packets > ae.Packets {
					t.Fatalf("filtered packets %d > all packets %d for protocol %q",
						fe.Packets, ae.Packets, fe.Protocol)
				}
				found = true
				break
			}
		}
		if !found {
			t.Errorf("filtered protocol %q not found in all entries", fe.Protocol)
		}
	}
}

func TestSessionProtocolHierarchy_MatchesFreeFunction(t *testing.T) {
	pcap := testfixture.Pcap(t)

	freeEntries, err := ProtocolHierarchy(pcap, WithDisplayFilter("frame.number <= 5"))
	if err != nil {
		t.Fatalf("ProtocolHierarchy: %v", err)
	}

	s, err := openSession(pcap)
	if err != nil {
		t.Fatalf("OpenSession: %v", err)
	}
	defer s.Close()

	sessionEntries, err := s.ProtocolHierarchy(Query{Filter: "frame.number <= 5"})
	if err != nil {
		t.Fatalf("Session.ProtocolHierarchy: %v", err)
	}

	if len(freeEntries) != len(sessionEntries) {
		t.Fatalf("free len %d != session len %d", len(freeEntries), len(sessionEntries))
	}
	for i := range freeEntries {
		if freeEntries[i].Protocol != sessionEntries[i].Protocol ||
			freeEntries[i].Packets != sessionEntries[i].Packets ||
			freeEntries[i].Bytes != sessionEntries[i].Bytes {
			t.Fatalf("mismatch at index %d: free=%+v session=%+v",
				i, freeEntries[i], sessionEntries[i])
		}
	}
}

func TestProtocolHierarchy_InvalidFilter(t *testing.T) {
	pcap := testfixture.Pcap(t)

	_, err := ProtocolHierarchy(pcap, WithDisplayFilter("bogus_field == 42"))
	if err == nil {
		t.Fatal("expected error for invalid filter")
	}
}

func TestProtocolHierarchy_ClosedSession(t *testing.T) {
	pcap := testfixture.Pcap(t)

	s, err := openSession(pcap)
	if err != nil {
		t.Fatalf("OpenSession: %v", err)
	}
	s.Close()

	_, err = s.ProtocolHierarchy(Query{})
	if err == nil {
		t.Fatal("expected error for closed session")
	}
}
