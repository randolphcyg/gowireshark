package gowireshark

import (
	"bytes"
	"io"
	"strings"

	"github.com/bytedance/sonic"
)

// WriteFramesJSONL writes selected frame dissections as newline-delimited JSON.
// Without WithOutputFields it streams libwireshark's raw JSON directly. With
// WithOutputFields it emits one compact object per frame keyed by requested
// field name, e.g. {"frame.number":"1","ip.src":"10.0.0.1"}.
func WriteFramesJSONL(path string, w io.Writer, opts ...Option) (int, error) {
	return WriteFrames(path, w, opts...)
}

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
