package utils

import (
	"crypto/rand"
	"crypto/subtle"
	"go.dedis.ch/onet/v3/log"
	"testing"
)

func TestBytesToUint64(t *testing.T) {
	for i := 1; i < 1000; i++ {
		data := make([]byte, i*5)
		n, err := rand.Read(data)
		if n != i*5 || err != nil {
			t.Fatal("Could not read data in buffer")
		}

		uints, err := BytesToUint64(data)
		if err != nil {
			t.Fatal(err)
		}
		//log.Lvl1(uints)

		dataRes, err := Uint64ToBytes(uints)
		if err != nil {
			t.Fatal(err)
		}
		if subtle.ConstantTimeCompare(dataRes, data) == 0 {
			log.Lvlf1("\nExpected:  %x \n Result:   %x ", data, dataRes)
			t.Fatal("End array and start array differ :")

		}
	}
}
