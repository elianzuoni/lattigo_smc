package services

import (
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"lattigo-smc/utils"
	"testing"
	"time"
)

func TestSetupCollectiveKey(t *testing.T) {
	log.SetDebugVisible(1)
	log.Lvl1("Testing if setup is done properly for the service")
	//turning off test.
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
	log.SetDebugVisible(4)
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

	q, err := client1.SendKeyRequest(true, false, false)
	log.Lvl1("Response of query : ", q)

	queryID, err := client1.SendWriteQuery(el, []byte("lattigood"))
	if err != nil {
		t.Fatal("Could not start client :", err)

	}

	log.Lvl2("Query Id : ", queryID)
	<-time.After(1 * time.Second)

}

func TestSwitching(t *testing.T) {
	log.SetDebugVisible(4)
	size := 3
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
	q, _ := client1.SendKeyRequest(true, false, false)
	<-time.After(200 * time.Millisecond)
	log.Lvl1("Reply of key request : ", q)
	content := []byte("lattigood")
	queryID, err := client1.SendWriteQuery(el, content)
	if err != nil {
		t.Fatal("Could not start client :", err)

	}

	log.Lvl2("Query Local Id : ", queryID, " with content : ", content)
	<-time.After(500 * time.Millisecond)

	//Client 2 now requests to switch the key for him...
	client2 := NewLattigoSMCClient(el.List[2], "2")
	data, err := client2.GetPlaintext(el, queryID)
	log.Lvl1("Client retrieved data : ", data)

	<-time.After(1000 * time.Second)

}
