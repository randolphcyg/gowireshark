// Package gowireshark exposes libwireshark-backed packet dissection helpers.
//
// libwireshark keeps process-global capture state, so Session is intentionally a
// process-wide exclusive resource: at most one active Session may exist at once.
//
// Use the offline APIs when packets already live in a pcap file:
//
//	frames, hasMore, err := gowireshark.FramesPage("capture.pcap", 1, 20)
//
// Use DissectPacket when packet acquisition belongs to another component:
//
//	frame, err := gowireshark.DissectPacket(gowireshark.RawPacket{
//		Data:           ethernetFrame,
//		CaptureLength:  len(ethernetFrame),
//		OriginalLength: len(ethernetFrame),
//		LinkType:       gowireshark.LinkTypeEthernet,
//	})
package gowireshark
