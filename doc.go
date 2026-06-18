// Package gowireshark exposes libwireshark-backed packet dissection helpers.
//
// libwireshark keeps process-global capture state, so Session is intentionally a
// process-wide exclusive resource: at most one active Session may exist at once.
//
// # Concurrency contract
//
//   - Session methods are NOT safe for concurrent use. A process-wide gate
//     (sessionGate) allows only one open Session at a time; epanMu serializes
//     every underlying C call.
//   - While epanMu is held (inside any Session method or free-function dissection
//     path), do NOT re-enter other Session/free-function APIs — doing so
//     deadlocks on epanMu.
//   - IterFrames / IterFrameJSON / IterFieldsRows spawn an internal goroutine
//     that holds epanMu for the duration of the iteration. The returned
//     iterator MUST be Closed to release epanMu and the session gate; failing
//     to Close leaks the lock and blocks all subsequent dissection.
//   - FilesContext opens a Session internally; its fallback path reuses that
//     same Session (s.WalkFrames) rather than opening a second one — opening a
//     second Session while the first is still open deadlocks on sessionGate.
//
// # Large-file path preference (cheapest first)
//
//  1. IterFrameJSON / IterFieldsRows — stream one frame at a time, no full
//     FrameData materialisation.
//  2. WriteFrames / WriteFieldsRows / WriteDissection(...) — write directly to
//     an io.Writer.
//  3. FieldsRows with a narrow display filter — field-only extraction.
//  4. Session cache with FramesPage — paginated access reuses cached results.
//  5. Frames / WalkFrames / WriteDissection(OutputPDML) — full parse into
//     memory; avoid for large captures.
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
