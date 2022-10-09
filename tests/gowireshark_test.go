package tests

import (
	"fmt"
	"testing"
	"time"

	"github.com/randolphcyg/gowireshark"
)

const inputFilepath = "../pcaps/s7comm_clean.pcap"

func TestEpanVersion(t *testing.T) {
	fmt.Println(gowireshark.EpanVersion())
}

func TestEpanPluginsSupported(t *testing.T) {
	fmt.Println(gowireshark.EpanPluginsSupported())
}

func TestDissectPrintFirstFrame(t *testing.T) {
	err := gowireshark.DissectPrintFirstFrame(inputFilepath)
	if err != nil {
		fmt.Println(err)
	}

}

func TestDissectPrintAllFrame(t *testing.T) {
	err := gowireshark.DissectPrintAllFrame(inputFilepath)
	if err != nil {
		fmt.Println(err)
	}

}

func TestDissectPrintFirstSeveralFrame(t *testing.T) {
	err := gowireshark.DissectPrintFirstSeveralFrame(inputFilepath, 200)
	if err != nil {
		fmt.Println(err)
	}

}

func TestDissectPrintSpecificFrame(t *testing.T) {
	err := gowireshark.DissectPrintSpecificFrame(inputFilepath, 5000)
	if err != nil {
		fmt.Println(err)
	}
}

func TestDissectPrintSpecificFrameByGo(t *testing.T) {
	err := gowireshark.DissectPrintSpecificFrameByGo(inputFilepath, 5000)
	if err != nil {
		fmt.Println(err)
	}
}

/*
RESULT: none
*/
func TestDissectPrintSpecificFrameOutOfBounds(t *testing.T) {
	err := gowireshark.DissectPrintSpecificFrame(inputFilepath, 5448)
	if err != nil {
		fmt.Println(err)
	}
}

/*
RESULT: 5448: frame index is out of bounds
*/
func TestDissectPrintSpecificFrameByGoOutOfBounds(t *testing.T) {
	err := gowireshark.DissectPrintSpecificFrame(inputFilepath, 5448)
	if err != nil {
		fmt.Println(err)
	}
}

func TestGetSpecificFrameHexData(t *testing.T) {
	res, err := gowireshark.GetSpecificFrameHexData(inputFilepath, 3)
	if err != nil {
		fmt.Println(err)
	}

	for i, item := range res.Offset {
		fmt.Println(i, item)
	}
	for i, item := range res.Hex {
		fmt.Println(i, item)
	}
	for i, item := range res.Ascii {
		fmt.Println(i, item)
	}
}

/*
	{
		"1": {
			"_index": "packets-20xx-0x-0x",
			"offset": ["0000", "0010", ...],
			"hex": ["00 1c 06 1c 69 e4 20 47 47 87 d4 96 08 00 45 00", ...],
			"ascii": ["....i. GG.....E.", ...],
			"_source": {
				"layers": {
	                "frame": {
						...
					},
					"eth": {
						"eth.dst": "00:1c:06:1c:69:e4",
						"eth.dst_tree": {
	                        ...
						}
					},
	                ...
				}
			}
		},
	    ...
	}
*/
func TestGetSpecificFrameProtoTreeInJson(t *testing.T) {
	specificFrameDissectRes, err := gowireshark.GetSpecificFrameProtoTreeInJson(inputFilepath, 3)
	if err != nil {
		fmt.Println(err)
	}

	for k, frameData := range specificFrameDissectRes {
		fmt.Println("# Frame num:" + k)
		fmt.Println("## WsIndex:", frameData.WsIndex)
		fmt.Println("## Offset:", frameData.Offset)
		fmt.Println("## Hex:", frameData.Hex)
		fmt.Println("## Ascii:", frameData.Ascii)
		fmt.Println("## Layers:")
		for layer, layerData := range frameData.WsSource.Layers {
			fmt.Println("### Layers num:", layer, layerData)
		}
	}

}

func TestGetAllFrameProtoTreeInJson(t *testing.T) {
	allFrameDissectRes, err := gowireshark.GetAllFrameProtoTreeInJson(inputFilepath)
	if err != nil {
		fmt.Println(err)
	}

	// Do not print the content in case the amount of data is too large
	fmt.Printf("frame count:%d\n", len(allFrameDissectRes))
}

/*
Get interface device list, TODO but not return addresses of device (cause c logic error)
Result:
bluetooth-monitor Bluetooth Linux Monitor 56
nflog Linux netfilter log (NFLOG) interface 48
nfqueue Linux netfilter queue (NFQUEUE) interface 48
dbus-system D-Bus system bus 48
dbus-session D-Bus session bus 48
enp0s5  22
any Pseudo-device that captures on all interfaces 54
lo  55
*/
func TestGetIfaceList(t *testing.T) {
	iFaces, err := gowireshark.GetIfaceList()
	if err != nil {
		fmt.Println(err)
	}
	for k, v := range iFaces {
		fmt.Println(k, v.Description, v.Flags)
	}
}

/*
Get interface device nonblock status, default is false
Result:
device: enp0s5  nonblock status: false
*/
func TestGetIfaceNonblockStatus(t *testing.T) {
	ifaceName := "enp0s5"
	status, err := gowireshark.GetIfaceNonblockStatus(ifaceName)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("device:", ifaceName, " nonblock status:", status)
}

func TestSetIfaceNonblockStatus(t *testing.T) {
	ifaceName := "enp0s5"
	status, err := gowireshark.SetIfaceNonblockStatus(ifaceName, true)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("device:", ifaceName, "after set, now nonblock status is:", status)
}

// BlockForever causes it to block forever waiting for packets, when passed
// into SetTimeout or OpenLive, while still returning incoming packets to userland relatively
// quickly.
const BlockForever = -time.Millisecond * 10

func timeoutMillis(timeout time.Duration) int {
	// Flip sign if necessary.  See package docs on timeout for reasoning behind this.
	if timeout < 0 {
		timeout *= -1
	}
	// Round up
	if timeout != 0 && timeout < time.Millisecond {
		timeout = time.Millisecond
	}
	return int(timeout / time.Millisecond)
}

var (
	ifaceName         = "enp0s5"
	snapshotLen int32 = 1024
	timeout           = 30 * time.Second
	err         error
)

func TestDissectPktLive(t *testing.T) {
	err = gowireshark.DissectPktLive(ifaceName, int(snapshotLen), 1, timeoutMillis(timeout))
	if err != nil {
		fmt.Println(err)
	}

}
