package gowireshark

/*
#include "bridge.h"
*/
import "C"
import (
	"context"
	"strings"
	"unsafe"

	"github.com/bytedance/sonic"
	"github.com/pkg/errors"
)

// ProtocolInfo describes one Wireshark protocol registered in libwireshark.
type ProtocolInfo struct {
	ID         int    `json:"id"`
	Name       string `json:"name"`
	ShortName  string `json:"shortName"`
	LongName   string `json:"longName"`
	FilterName string `json:"filterName"`
	Enabled    bool   `json:"enabled"`
}

// FieldMetadata describes one registered Wireshark display-filter field.
type FieldMetadata struct {
	ID             int    `json:"id"`
	Name           string `json:"name"`
	Abbrev         string `json:"abbrev"`
	Type           string `json:"type"`
	Display        string `json:"display"`
	Blurb          string `json:"blurb"`
	ParentID       int    `json:"parentID"`
	ParentName     string `json:"parentName"`
	ParentProtocol string `json:"parentProtocol"`
	Bitmask        string `json:"bitmask"`
	IsProtocol     bool   `json:"isProtocol"`
}

func RuntimeProtocols(ctx context.Context) ([]ProtocolInfo, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	epanMu.Lock()
	defer epanMu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	raw := C.gowireshark_protocols_json()
	if raw == nil {
		return nil, errors.New("protocol metadata unavailable")
	}
	defer C.free(unsafe.Pointer(raw))

	var out []ProtocolInfo
	if err := sonic.UnmarshalString(C.GoString(raw), &out); err != nil {
		return nil, err
	}
	return out, nil
}

func RuntimeSuggestFields(ctx context.Context, prefix string, limit int) ([]FieldMetadata, error) {
	all, err := RuntimeFields(ctx)
	if err != nil {
		return nil, err
	}

	prefix = strings.ToLower(prefix)
	out := make([]FieldMetadata, 0)
	for _, f := range all {
		if strings.HasPrefix(strings.ToLower(f.Abbrev), prefix) {
			out = append(out, f)
			if limit > 0 && len(out) >= limit {
				break
			}
		}
	}
	return out, nil
}

func RuntimeFields(ctx context.Context) ([]FieldMetadata, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	epanMu.Lock()
	defer epanMu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	raw := C.gowireshark_fields_json()
	if raw == nil {
		return nil, errors.New("field metadata unavailable")
	}
	defer C.free(unsafe.Pointer(raw))

	var out []FieldMetadata
	if err := sonic.UnmarshalString(C.GoString(raw), &out); err != nil {
		return nil, err
	}
	return out, nil
}

// FieldInfo returns metadata for one display-filter field.
//
// The return type is FieldMetadata because Go does not allow a function and a
// type to share the same exported identifier.
func FieldInfo(name string) (*FieldMetadata, error) {
	if name == "" {
		return nil, errors.Wrap(ErrInvalidField, name)
	}

	epanMu.Lock()
	defer epanMu.Unlock()

	cName := C.CString(name)
	defer C.free(unsafe.Pointer(cName))

	raw := C.gowireshark_field_json(cName)
	if raw == nil {
		return nil, errors.Wrap(ErrInvalidField, name)
	}
	defer C.free(unsafe.Pointer(raw))
	rawGo := C.GoString(raw)
	if rawGo == "" {
		return nil, errors.Wrap(ErrInvalidField, name)
	}

	var out FieldMetadata
	if err := sonic.UnmarshalString(rawGo, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ValidateField verifies that name is a registered Wireshark display-filter field.
func ValidateField(name string) error {
	_, err := FieldInfo(name)
	return err
}

type VersionInfo struct {
	Version         string `json:"version"`
	CompiledVersion string `json:"compiledVersion"`
	Copyright       string `json:"copyright"`
}

// RuntimeVersion returns structured version information from the linked
// Wireshark runtime.
func RuntimeVersion(ctx context.Context) (*VersionInfo, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	epanMu.Lock()
	defer epanMu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	raw := C.gowireshark_version_json()
	if raw == nil {
		return nil, errors.New("version info unavailable")
	}
	defer C.free(unsafe.Pointer(raw))

	var out VersionInfo
	if err := sonic.UnmarshalString(C.GoString(raw), &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func RuntimeProfiles(ctx context.Context) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	epanMu.Lock()
	defer epanMu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	raw := C.gowireshark_profiles_json()
	if raw == nil {
		return nil, errors.New("profiles unavailable")
	}
	defer C.free(unsafe.Pointer(raw))

	var out []string
	if err := sonic.UnmarshalString(C.GoString(raw), &out); err != nil {
		return nil, err
	}
	return out, nil
}

type DecodeAsTable struct {
	Name              string   `json:"name"`
	TableName         string   `json:"tableName"`
	NumItems          int      `json:"numItems"`
	DefaultIndexValue int      `json:"defaultIndexValue"`
	Choices           []string `json:"choices"`
}

func RuntimeDecodeAsTables(ctx context.Context) ([]DecodeAsTable, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	epanMu.Lock()
	defer epanMu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	raw := C.gowireshark_decode_as_tables_json()
	if raw == nil {
		return nil, errors.New("decode-as tables unavailable")
	}
	defer C.free(unsafe.Pointer(raw))

	var out []DecodeAsTable
	if err := sonic.UnmarshalString(C.GoString(raw), &out); err != nil {
		return nil, err
	}
	return out, nil
}

func RuntimeDecodeAsChoices(ctx context.Context, table string) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if table == "" {
		return nil, &DecodeAsError{Table: table, Message: "table name is empty"}
	}

	tables, err := RuntimeDecodeAsTables(ctx)
	if err != nil {
		return nil, err
	}
	found := false
	for _, tbl := range tables {
		if tbl.TableName == table || tbl.Name == table {
			found = true
			break
		}
	}
	if !found {
		return nil, &DecodeAsError{Table: table, Message: "table not registered"}
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}
	epanMu.Lock()
	defer epanMu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	cTable := C.CString(table)
	defer C.free(unsafe.Pointer(cTable))

	raw := C.gowireshark_decode_as_choices_json(cTable)
	if raw == nil {
		return nil, &DecodeAsError{Table: table, Message: "choices unavailable"}
	}
	defer C.free(unsafe.Pointer(raw))

	var out []string
	if err := sonic.UnmarshalString(C.GoString(raw), &out); err != nil {
		return nil, err
	}
	return out, nil
}

func RuntimeTapTypes(ctx context.Context) []string {
	if err := ctx.Err(); err != nil {
		return nil
	}
	epanMu.Lock()
	defer epanMu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil
	}

	raw := C.gowireshark_tap_types_json()
	if raw == nil {
		return nil
	}
	defer C.free(unsafe.Pointer(raw))

	var out []string
	if err := sonic.UnmarshalString(C.GoString(raw), &out); err != nil {
		return nil
	}
	return out
}

type PreferenceInfo struct {
	Name        string `json:"name"`
	Title       string `json:"title"`
	Description string `json:"description"`
	NumPrefs    int    `json:"numPrefs"`
	Obsolete    bool   `json:"obsolete"`
}

func RuntimePreferences(ctx context.Context) ([]PreferenceInfo, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	epanMu.Lock()
	defer epanMu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	raw := C.gowireshark_preferences_json()
	if raw == nil {
		return nil, errors.New("preferences unavailable")
	}
	defer C.free(unsafe.Pointer(raw))

	var out []PreferenceInfo
	if err := sonic.UnmarshalString(C.GoString(raw), &out); err != nil {
		return nil, err
	}
	return out, nil
}
