package gowireshark

/*
#include "bridge.h"
*/
import "C"
import (
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

// Protocols returns libwireshark's registered protocol metadata.
func Protocols() ([]ProtocolInfo, error) {
	epanMu.Lock()
	defer epanMu.Unlock()

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

// Fields returns libwireshark's registered display-filter field metadata.
func Fields() ([]FieldMetadata, error) {
	epanMu.Lock()
	defer epanMu.Unlock()

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
		return nil, errors.Wrap(ErrFieldNotFound, name)
	}

	epanMu.Lock()
	defer epanMu.Unlock()

	cName := C.CString(name)
	defer C.free(unsafe.Pointer(cName))

	raw := C.gowireshark_field_json(cName)
	if raw == nil {
		return nil, errors.Wrap(ErrFieldNotFound, name)
	}
	defer C.free(unsafe.Pointer(raw))
	rawGo := C.GoString(raw)
	if rawGo == "" {
		return nil, errors.Wrap(ErrFieldNotFound, name)
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
