package gowireshark

import "testing"

func TestSelectOutputFields(t *testing.T) {
	raw := []byte(`{"_index":"packets","layers":{"frame":{"frame.number":"7","frame.len":"128"},"ip":{"ip.src":"10.0.0.1","ip.dst":"10.0.0.2"},"tcp":{"tcp.stream":"3"}}}`)
	got, err := selectOutputFields(raw, []string{"frame.number", "ip.src", "tcp.stream", "missing.field"})
	if err != nil {
		t.Fatal(err)
	}
	if got["frame.number"] != "7" || got["ip.src"] != "10.0.0.1" || got["tcp.stream"] != "3" {
		t.Fatalf("unexpected fields: %#v", got)
	}
	if _, ok := got["missing.field"]; ok {
		t.Fatalf("missing field should be omitted: %#v", got)
	}
}
