package gowireshark

import (
	"testing"

	"github.com/randolphcyg/gowireshark/internal/testfixture"
)

func TestExpertInfosDoesNotCrash(t *testing.T) {
	pcap := testfixture.Pcap(t)

	infos, err := ExpertInfos(pcap)
	if err != nil {
		t.Fatalf("ExpertInfos: %v", err)
	}
	for _, info := range infos {
		if info.FrameNumber <= 0 {
			t.Fatalf("invalid expert frame number: %#v", info)
		}
	}
}

func TestSessionExpertInfosMatchesFreeFunction(t *testing.T) {
	pcap := testfixture.Pcap(t)

	freeInfos, err := ExpertInfos(pcap, WithDisplayFilter("frame.number <= 5"))
	if err != nil {
		t.Fatalf("ExpertInfos: %v", err)
	}

	s, err := OpenSession(pcap)
	if err != nil {
		t.Fatalf("OpenSession: %v", err)
	}
	defer s.Close()

	sessionInfos, err := s.ExpertInfos(Query{Filter: "frame.number <= 5"})
	if err != nil {
		t.Fatalf("Session.ExpertInfos: %v", err)
	}
	if len(sessionInfos) != len(freeInfos) {
		t.Fatalf("expert count mismatch: session=%d free=%d", len(sessionInfos), len(freeInfos))
	}
}
