package services

import (
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"lattigo-smc/protocols"
	"lattigo-smc/utils"
	"testing"
)

func TestSetup(t *testing.T) {
	log.Lvl1("Testing if setup is done properly for the service")
	//turning off test.
	protocols.TurnOffTest()
	size := 5
	local := onet.NewLocalTest(utils.SUITE)
	_, el, _ := local.GenTree(size, true)
	client := NewLattigoSMCClient(el.List[0], "0")
	//First the client needs to ask the parties to generate the keys.
	err := client.SendSetupQuery(el, false)
	if err != nil {
		t.Fatal("Could not setup the roster", err)
	}

	queryID, err := client.SendWriteQuery(el, "", "lattigo")
	if err != nil {
		t.Fatal("Could not start client :", err)

	}

	log.Lvl2("Query id : ", queryID)

}
