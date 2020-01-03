package services

import (
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"lattigo-smc/protocols"
	"lattigo-smc/utils"
	"testing"
	"time"
)

func TestSetupCollectiveKey(t *testing.T) {
	log.SetDebugVisible(1)
	log.Lvl1("Testing if setup is done properly for the service")
	//turning off test.
	protocols.TurnOffTest()
	size := 3
	local := onet.NewLocalTest(utils.SUITE)
	_, el, _ := local.GenTree(size, true)
	client := NewLattigoSMCClient(el.List[0], "0")
	//First the client needs to ask the parties to generate the keys.
	seed := []byte{'l', 'a', 't', 't', 'i', 'g', 'o'}
	err := client.SendSetupQuery(el, false, 0, seed)
	if err != nil {
		t.Fatal("Could not setup the roster", err)
	}

}

func TestWrite(t *testing.T) {
	protocols.TurnOffTest()
	size := 5
	local := onet.NewLocalTest(utils.SUITE)
	_, el, _ := local.GenTree(size, true)

	client := NewLattigoSMCClient(el.List[0], "0")
	seed := []byte{'l', 'a', 't', 't', 'i', 'g', 'o'}

	err := client.SendSetupQuery(el, false, 0, seed)
	if err != nil {
		t.Fatal(err)
		return
	}
	<-time.After(2 * time.Second)
	client1 := NewLattigoSMCClient(el.List[1], "1")

	queryID, err := client1.SendWriteQuery(el, []byte("lattigood"))
	if err != nil {
		t.Fatal("Could not start client :", err)

	}

	log.Lvl2("Query id : ", queryID)

	<-time.After(10 * time.Second)

}
