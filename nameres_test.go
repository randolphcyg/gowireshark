package gowireshark

import (
	"errors"
	"testing"

	"github.com/randolphcyg/gowireshark/internal/testfixture"
)

func TestWithNameResolution_DoesNotCrash(t *testing.T) {
	pcap := testfixture.Pcap(t)

	frames, err := Frames(pcap, WithNameResolution(NameResolutionConfig{
		MAC:       true,
		Network:   true,
		Transport: true,
		External:  false,
	}))
	if err != nil {
		t.Fatalf("Frames with name resolution: %v", err)
	}
	if len(frames) == 0 {
		t.Fatal("expected non-empty frames")
	}
	t.Logf("parsed %d frames with name resolution enabled", len(frames))
}

func TestWithNameResolution_False(t *testing.T) {
	pcap := testfixture.Pcap(t)

	frames, err := Frames(pcap, WithNameResolution(NameResolutionConfig{
		MAC:       false,
		Network:   false,
		Transport: false,
		External:  false,
	}))
	if err != nil {
		t.Fatalf("Frames with name resolution disabled: %v", err)
	}
	if len(frames) == 0 {
		t.Fatal("expected non-empty frames")
	}
	t.Logf("parsed %d frames with name resolution disabled", len(frames))
}

func TestWithPreferences_DoesNotCrash(t *testing.T) {
	pcap := testfixture.Pcap(t)

	frames, err := Frames(pcap, WithPreferences([]Preference{
		{Name: "tcp.desegment_tcp_streams", Value: "TRUE"},
	}))
	if err != nil {
		t.Fatalf("Frames with preferences: %v", err)
	}
	if len(frames) == 0 {
		t.Fatal("expected non-empty frames")
	}
	t.Logf("parsed %d frames with custom preference", len(frames))
}

func TestWithProfile_Default(t *testing.T) {
	pcap := testfixture.Pcap(t)

	frames, err := Frames(pcap, WithProfile("Default"))
	if err != nil {
		t.Fatalf("Frames with Default profile: %v", err)
	}
	if len(frames) == 0 {
		t.Fatal("expected non-empty frames")
	}
	t.Logf("parsed %d frames with Default profile", len(frames))
}

func TestWithProfile_Nonexistent(t *testing.T) {
	pcap := testfixture.Pcap(t)

	_, err := Frames(pcap, WithProfile("nonexistent_profile_xyz"))
	if err == nil {
		t.Fatal("expected error for nonexistent profile, got nil")
	}
	if !errors.Is(err, ErrInvalidProfile) {
		t.Fatalf("expected ErrInvalidProfile, got %v", err)
	}
	t.Logf("correctly rejected nonexistent profile: %v", err)
}

func TestWithPreferences_Session(t *testing.T) {
	pcap := testfixture.Pcap(t)

	s, err := OpenSession(pcap, WithPreferences([]Preference{
		{Name: "tcp.desegment_tcp_streams", Value: "TRUE"},
	}))
	if err != nil {
		t.Fatalf("OpenSession with preferences: %v", err)
	}
	defer s.Close()

	frames, _, err := s.FramesPage(Query{}, 1, 5)
	if err != nil {
		t.Fatalf("FramesPage: %v", err)
	}
	if len(frames) == 0 {
		t.Fatal("expected non-empty frames")
	}
}

func TestWithNameResolution_Session(t *testing.T) {
	pcap := testfixture.Pcap(t)

	s, err := OpenSession(pcap, WithNameResolution(NameResolutionConfig{
		Network:   true,
		Transport: true,
	}))
	if err != nil {
		t.Fatalf("OpenSession with name resolution: %v", err)
	}
	defer s.Close()

	frames, _, err := s.FramesPage(Query{}, 1, 5)
	if err != nil {
		t.Fatalf("FramesPage: %v", err)
	}
	if len(frames) == 0 {
		t.Fatal("expected non-empty frames")
	}
}