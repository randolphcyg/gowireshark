package tests

import (
	"fmt"
	"testing"

	"github.com/randolphcyg/gowireshark"
)

func TestEpanVersion(t *testing.T) {
	fmt.Println(gowireshark.EpanVersion())
}

func TestEpanPluginsSupported(t *testing.T) {
	fmt.Println(gowireshark.EpanPluginsSupported())
}

func TestDissectFirstPkt(t *testing.T) {
	fmt.Println("Parse the first package of the data package file")

	filepath := "../pcaps/s7comm_clean.pcap"
	err := gowireshark.DissectFirstPkt(filepath)
	if err != nil {
		fmt.Println(err)
	}

}

func TestDissectAllPkt(t *testing.T) {
	fmt.Println("Test to parse all packages in the data package file")

	filepath := "../pcaps/s7comm_clean.pcap"
	err := gowireshark.DissectAllPkt(filepath)
	if err != nil {
		fmt.Println(err)
	}

}
