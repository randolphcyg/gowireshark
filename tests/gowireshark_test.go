package tests

import (
	"encoding/json"
	"fmt"
	"testing"

	log "github.com/sirupsen/logrus"

	"github.com/randolphcyg/gowireshark"
)

const inputFilepath = "../pcaps/s7comm_clean.pcap"

func TestEpanVersion(t *testing.T) {
	fmt.Println(gowireshark.EpanVersion())
}

func TestEpanPluginsSupported(t *testing.T) {
	fmt.Println(gowireshark.EpanPluginsSupported())
}

func TestDissectAllFrame(t *testing.T) {
	err := gowireshark.DissectAllFrame(inputFilepath)
	if err != nil {
		fmt.Println(err)
	}

}

func TestDissectFirstFrame(t *testing.T) {
	err := gowireshark.DissectFirstFrame(inputFilepath)
	if err != nil {
		fmt.Println(err)
	}

}

func TestDissectFirstSeveralFrame(t *testing.T) {
	err := gowireshark.DissectFirstSeveralFrame(inputFilepath, 2000)
	if err != nil {
		fmt.Println(err)
	}

}

func TestDissectSpecificFrame(t *testing.T) {
	err := gowireshark.DissectSpecificFrame(inputFilepath, 5000)
	if err != nil {
		fmt.Println(err)
	}
}

/*
RESULT: none
*/
func TestDissectSpecificFrameOutOfBounds(t *testing.T) {
	err := gowireshark.DissectSpecificFrame(inputFilepath, 5448)
	if err != nil {
		fmt.Println(err)
	}
}

func TestDissectSpecificFrameByGo(t *testing.T) {
	err := gowireshark.DissectSpecificFrame(inputFilepath, 5000)
	if err != nil {
		fmt.Println(err)
	}
}

/*
RESULT: 5448: frame index is out of bounds
*/
func TestDissectSpecificFrameByGoOutOfBounds(t *testing.T) {
	err := gowireshark.DissectSpecificFrame(inputFilepath, 5448)
	if err != nil {
		fmt.Println(err)
	}
}

func TestGetSpecificFrameHexData(t *testing.T) {
	resBytes, err := gowireshark.GetSpecificFrameHexData(inputFilepath, 3)
	if err != nil {
		fmt.Println(err)
	}

	fmt.Printf("%s\n", resBytes)
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
func TestProtoTreeToJsonSpecificFrame(t *testing.T) {
	specificFrameDissectRes, err := gowireshark.ProtoTreeToJsonSpecificFrame(inputFilepath, 3)
	if err != nil {
		fmt.Println(err)
	}

	resBytes, err := json.Marshal(specificFrameDissectRes)
	if err != nil {
		log.Error(err)
		return
	}

	fmt.Printf("%s\n", resBytes)
}

func TestProtoTreeToJsonAllFrame(t *testing.T) {
	allFrameDissectRes, err := gowireshark.ProtoTreeToJsonAllFrame(inputFilepath)
	if err != nil {
		fmt.Println(err)
	}

	resBytes, err := json.Marshal(allFrameDissectRes)
	if err != nil {
		log.Error(err)
		return
	}

	fmt.Printf("%s\n", resBytes)
	fmt.Printf("%d\n", len(resBytes))
}
