package gowireshark

import (
	"bufio"
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/bytedance/sonic"
)

func writeFrameJSONLine(w io.Writer, jsonBytes []byte, conf *config) error {
	if len(conf.OutputFields) == 0 {
		_, err := w.Write(jsonBytes)
		if err != nil {
			return err
		}
		_, err = w.Write([]byte("\n"))
		return err
	}

	selected, err := selectOutputFields(jsonBytes, conf.OutputFields)
	if err != nil {
		return err
	}
	line, err := sonic.Marshal(selected)
	if err != nil {
		return err
	}
	_, err = w.Write(line)
	if err != nil {
		return err
	}
	_, err = w.Write([]byte("\n"))
	return err
}

func selectOutputFields(jsonBytes []byte, fields []string) (map[string]any, error) {
	var root map[string]any
	dec := sonic.ConfigDefault.NewDecoder(bytes.NewReader(jsonBytes))
	dec.UseNumber()
	if err := dec.Decode(&root); err != nil {
		return nil, err
	}

	out := make(map[string]any, len(fields))
	for _, field := range fields {
		field = strings.TrimSpace(field)
		if field == "" {
			continue
		}
		if v, ok := lookupOutputField(root, field); ok {
			out[field] = v
		}
	}
	return out, nil
}

func lookupOutputField(root map[string]any, field string) (any, bool) {
	if v, ok := root[field]; ok {
		return v, true
	}
	if layersAny, ok := root["layers"]; ok {
		if layersMap, ok := layersAny.(map[string]any); ok {
			if v, ok := lookupLayerField(layersMap, field); ok {
				return v, true
			}
		}
	}
	return lookupFieldRecursive(root, field)
}

func lookupLayerField(layersMap map[string]any, field string) (any, bool) {
	layerName := outputLayerName(field)
	if layerName != "" {
		if layerAny, ok := layersMap[layerName]; ok {
			if layerMap, ok := layerAny.(map[string]any); ok {
				if v, ok := layerMap[field]; ok {
					return v, true
				}
			}
		}
	}
	for _, layerAny := range layersMap {
		if layerMap, ok := layerAny.(map[string]any); ok {
			if v, ok := layerMap[field]; ok {
				return v, true
			}
		}
	}
	return nil, false
}

func outputLayerName(field string) string {
	if strings.HasPrefix(field, "_ws.col.") {
		return "_ws.col"
	}
	if i := strings.IndexByte(field, '.'); i > 0 {
		return field[:i]
	}
	return ""
}

func lookupFieldRecursive(v any, field string) (any, bool) {
	switch x := v.(type) {
	case map[string]any:
		if val, ok := x[field]; ok {
			return val, true
		}
		for _, child := range x {
			if val, ok := lookupFieldRecursive(child, field); ok {
				return val, true
			}
		}
	case []any:
		for _, child := range x {
			if val, ok := lookupFieldRecursive(child, field); ok {
				return val, true
			}
		}
	}
	return nil, false
}

const (
	pdmlHeader = `<?xml version="1.0" encoding="utf-8"?>
<pdml version="0" creator="gowireshark">
`
	pdmlFooter = "</pdml>\n"
)

const (
	psmlHeader = `<?xml version="1.0" encoding="utf-8"?>
<psml version="0" creator="gowireshark">
<structure>
<section>No.,Time,Source,Destination,Protocol,Length,Info</section>
</structure>
`
	psmlFooter = "</psml>\n"
)

type pdmlWriter struct {
	w io.Writer
	n int
}

func (pw *pdmlWriter) write(s string) error {
	m, err := io.WriteString(pw.w, s)
	pw.n += m
	return err
}

func (s *Session) writePDML(w io.Writer, q Query) (int, error) {
	bw := bufio.NewWriter(w)
	pw := &pdmlWriter{w: bw}
	if err := pw.write(pdmlHeader); err != nil {
		return 0, err
	}

	count := 0
	walkErr := s.walkFramesLocked(q, func(f *FrameData) error {
		if err := writePacketPDML(pw, f); err != nil {
			return err
		}
		count++
		return nil
	})
	if walkErr != nil {
		return count, walkErr
	}

	if err := pw.write(pdmlFooter); err != nil {
		return count, err
	}
	if err := bw.Flush(); err != nil {
		return count, err
	}
	return count, nil
}

func writePacketPDML(pw *pdmlWriter, f *FrameData) error {
	if err := pw.write("  <packet>\n"); err != nil {
		return err
	}

	protoNames := make([]string, 0, len(f.Layers))
	for name := range f.Layers {
		protoNames = append(protoNames, name)
	}
	sort.Slice(protoNames, func(i, j int) bool {
		return layerOrder(protoNames[i]) < layerOrder(protoNames[j])
	})

	for _, name := range protoNames {
		layer := f.Layers[name]
		if err := writeProtoPDML(pw, name, layer, "    "); err != nil {
			return err
		}
	}

	if err := pw.write("  </packet>\n"); err != nil {
		return err
	}
	return nil
}

func layerOrder(name string) int {
	switch name {
	case "frame":
		return 0
	case "eth":
		return 1
	case "ip":
		return 2
	case "ipv6":
		return 3
	case "tcp":
		return 4
	case "udp":
		return 5
	case "sctp":
		return 6
	default:
		return 100
	}
}

func writeProtoPDML(pw *pdmlWriter, name string, layer any, indent string) error {
	protoMap, ok := layer.(map[string]any)
	if !ok {
		return nil
	}

	if err := pw.write(fmt.Sprintf("%s<proto name=\"%s\">\n", indent, xmlEscape(name))); err != nil {
		return err
	}

	keys := make([]string, 0, len(protoMap))
	for k := range protoMap {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, key := range keys {
		if strings.HasSuffix(key, "_tree") {
			childLayer, ok := protoMap[key].(map[string]any)
			if !ok {
				continue
			}
			baseName := strings.TrimSuffix(key, "_tree")
			if err := writeProtoPDML(pw, baseName, childLayer, indent+"  "); err != nil {
				return err
			}
			continue
		}

		strVal := anyToString(protoMap[key])
		if err := pw.write(fmt.Sprintf("%s  <field name=\"%s\" show=\"%s\" value=\"%s\"/>\n",
			indent, xmlEscape(key), xmlEscape(strVal), xmlEscape(strVal))); err != nil {
			return err
		}
	}

	if err := pw.write(fmt.Sprintf("%s</proto>\n", indent)); err != nil {
		return err
	}
	return nil
}

func anyToString(v any) string {
	switch val := v.(type) {
	case string:
		return val
	case float64:
		return fmt.Sprintf("%g", val)
	case bool:
		if val {
			return "1"
		}
		return "0"
	case map[string]any:
		return ""
	case []any:
		parts := make([]string, len(val))
		for i, item := range val {
			parts[i] = anyToString(item)
		}
		return strings.Join(parts, ",")
	default:
		return fmt.Sprintf("%v", val)
	}
}

func xmlEscape(s string) string {
	var buf strings.Builder
	xml.EscapeText(&buf, []byte(s))
	return buf.String()
}

func (s *Session) writePSML(w io.Writer, q Query) (int, error) {
	epanMu.Lock()
	defer epanMu.Unlock()
	defer cleanupGlobalState()

	if err := s.resetReadPosition(); err != nil {
		return 0, err
	}

	bw := bufio.NewWriter(w)
	pw := &pdmlWriter{w: bw}
	if err := pw.write(psmlHeader); err != nil {
		return 0, err
	}

	count, err := writePSMLFast(q.Filter, pw)
	s.readPositionDirty.Store(true)
	if err != nil {
		return count, err
	}

	if fErr := pw.write(psmlFooter); fErr != nil {
		return count, fErr
	}
	if fErr := bw.Flush(); fErr != nil {
		return count, fErr
	}
	return count, nil
}

func writePSMLFast(filter string, pw *pdmlWriter) (int, error) {
	if err := ValidateFilter(filter); err != nil {
		return 0, err
	}

	fields := []string{
		"frame.number", "frame.time_relative",
		"ip.src", "ip.dst",
		"_ws.col.protocol", "frame.len", "_ws.col.info",
	}

	count := 0
	var writeErr error

	globalFrameSink = func(jsonBytes []byte) bool {
		var row map[string]string
		if uErr := sonic.Unmarshal(jsonBytes, &row); uErr != nil {
			writeErr = uErr
			return false
		}
		no := row["frame.number"]
		timeVal := row["frame.time_relative"]
		src := row["ip.src"]
		dst := row["ip.dst"]
		proto := row["_ws.col.protocol"]
		length := row["frame.len"]
		info := row["_ws.col.info"]

		section := fmt.Sprintf("%s,%s,%s,%s,%s,%s,%s",
			no, timeVal, src, dst, proto, length, xmlEscape(info))
		if e := pw.write(fmt.Sprintf("<packet>\n  <section>%s</section>\n</packet>\n", xmlEscape(section))); e != nil {
			writeErr = e
			return false
		}
		count++
		return true
	}

	if err := sessionWalkFieldsFast(filter, fields); err != nil {
		return count, err
	}
	return count, writeErr
}

func (s *Session) writeText(w io.Writer, q Query) (int, error) {
	epanMu.Lock()
	defer epanMu.Unlock()
	defer cleanupGlobalState()

	if err := s.resetReadPosition(); err != nil {
		return 0, err
	}

	count, err := writeTextFast(q.Filter, w)
	s.readPositionDirty.Store(true)
	return count, err
}

func writeTextFast(filter string, w io.Writer) (int, error) {
	if err := ValidateFilter(filter); err != nil {
		return 0, err
	}

	fields := []string{
		"frame.number", "frame.time_relative", "frame.len", "frame.protocols",
		"_ws.col.info", "_ws.col.protocol", "_ws.col.def_src", "_ws.col.def_dst",
	}

	count := 0
	var writeErr error

	globalFrameSink = func(jsonBytes []byte) bool {
		var row map[string]string
		if uErr := sonic.Unmarshal(jsonBytes, &row); uErr != nil {
			writeErr = uErr
			return false
		}
		no := row["frame.number"]
		timeVal := row["frame.time_relative"]
		src := row["_ws.col.def_src"]
		dst := row["_ws.col.def_dst"]
		proto := row["_ws.col.protocol"]
		length := row["frame.len"]
		protoTree := row["frame.protocols"]
		info := row["_ws.col.info"]

		line := fmt.Sprintf("Frame %s: %s  %s → %s  %s  %s bytes",
			no, timeVal, src, dst, proto, length)
		if protoTree != "" {
			line += fmt.Sprintf("  [%s]", protoTree)
		}
		if info != "" {
			line += fmt.Sprintf("  %s", info)
		}
		line += "\n"
		if _, wErr := w.Write([]byte(line)); wErr != nil {
			writeErr = wErr
			return false
		}
		count++
		return true
	}

	if err := sessionWalkFieldsFast(filter, fields); err != nil {
		return count, err
	}
	return count, writeErr
}
