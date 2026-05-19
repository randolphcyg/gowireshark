package gowireshark

/*
#include "offline.h"
#include <stdlib.h>

extern int onFrameCallback(char *json, int len, int err);

static int call_get_expert_infos_cb(char *filter) {
    return get_expert_infos_cb(filter, onFrameCallback);
}
*/
import "C"
import (
	"unsafe"

	"github.com/bytedance/sonic"
	"github.com/pkg/errors"
)

// ExpertInfo is one Wireshark Expert Info finding emitted by libwireshark's
// expert tap during dissection.
type ExpertInfo struct {
	FrameNumber int    `json:"frameNumber"`
	Severity    string `json:"severity,omitempty"`
	Group       string `json:"group,omitempty"`
	Protocol    string `json:"protocol,omitempty"`
	Summary     string `json:"summary,omitempty"`
	Field       string `json:"field,omitempty"`
	Name        string `json:"name,omitempty"`
	Message     string `json:"message,omitempty"`
}

// ExpertInfos returns Expert Info records for frames matched by opts.
func ExpertInfos(path string, opts ...Option) ([]ExpertInfo, error) {
	epanMu.Lock()
	defer epanMu.Unlock()

	conf, err := initCapFile(path, opts...)
	if err != nil {
		return nil, err
	}
	if conf.DisplayFilter != "" {
		if err := ValidateFilter(conf.DisplayFilter); err != nil {
			return nil, err
		}
	}
	return expertInfosFromActive(conf.DisplayFilter)
}

// ExpertInfos returns Expert Info records for frames matched by q.
func (s *Session) ExpertInfos(q Query) ([]ExpertInfo, error) {
	if err := s.checkClosed(); err != nil {
		return nil, err
	}
	if q.Filter != "" {
		if err := ValidateFilter(q.Filter); err != nil {
			return nil, err
		}
	}

	epanMu.Lock()
	defer epanMu.Unlock()

	if err := sessionResetReadPosition(); err != nil {
		return nil, err
	}
	return expertInfosFromActive(q.Filter)
}

func expertInfosFromActive(filter string) ([]ExpertInfo, error) {
	out := make([]ExpertInfo, 0)
	var parseErr error

	globalFrameSink = func(jsonBytes []byte) bool {
		var info ExpertInfo
		if err := sonic.Unmarshal(jsonBytes, &info); err != nil {
			parseErr = err
			return false
		}
		out = append(out, info)
		return true
	}
	defer func() { globalFrameSink = nil }()

	cFilter := C.CString(filter)
	defer C.free(unsafe.Pointer(cFilter))

	if ret := C.call_get_expert_infos_cb(cFilter); ret != 0 {
		return out, errors.Wrapf(ErrReadCaptureFile, "expert tap failed: %d", int(ret))
	}
	if parseErr != nil {
		return out, parseErr
	}
	return out, nil
}
