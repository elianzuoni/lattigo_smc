package services

import (
	"github.com/golangplus/testing/assert"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"lattigo-smc/utils"
	"testing"
	"time"
)

func TestSetupCollectiveKeyGen(t *testing.T) {
	log.SetDebugVisible(1)
	log.Lvl1("Testing if setup is done properly for the service")
	//turning off test.
	size := 3
	local := onet.NewLocalTest(utils.SUITE)
	_, el, _ := local.GenTree(size, true)
	client := NewLattigoSMCClient(el.List[0], "0")
	//First the client needs to ask the parties to generate the keys.
	seed := []byte{'l', 'a', 't', 't', 'i', 'g', 'o'}
	err := client.SendSetupQuery(el, true, false, false, 0, 0, 0, seed)
	if err != nil {
		t.Fatal("Could not setup the roster", err)
	}

}

func TestSetupEvalKey(t *testing.T) {
	log.SetDebugVisible(1)
	log.Lvl1("Testing if setup for evaluation key is done properly for the service")
	//turning off test.
	size := 3
	local := onet.NewLocalTest(utils.SUITE)
	_, el, _ := local.GenTree(size, true)
	client := NewLattigoSMCClient(el.List[0], "0")
	//First the client needs to ask the parties to generate the keys.
	seed := []byte{'l', 'a', 't', 't', 'i', 'g', 'o'}
	err := client.SendSetupQuery(el, false, true, false, 0, 0, 0, seed)
	if err != nil {
		t.Fatal("Could not setup the roster", err)
	}
}

func TestSetupRotKey(t *testing.T) {
	log.SetDebugVisible(4)
	log.Lvl1("Testing if setup for rotation key is done properly for the service")
	//turning off test.
	size := 3
	local := onet.NewLocalTest(utils.SUITE)
	_, el, _ := local.GenTree(size, true)
	client := NewLattigoSMCClient(el.List[0], "0")
	//First the client needs to ask the parties to generate the keys.
	seed := []byte{'l', 'a', 't', 't', 'i', 'g', 'o'}
	err := client.SendSetupQuery(el, false, false, true, 1, 0, 0, seed)
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

	err := client.SendSetupQuery(el, true, false, false, 0, 0, 0, seed)
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

	err := client.SendSetupQuery(el, true, false, false, 0, 0, 0, seed)
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

	assert.Equal(t, "Result", string(data), string(content))

	<-time.After(1000 * time.Second)

}

func TestSumQuery(t *testing.T) {
	log.SetDebugVisible(4)
	size := 5
	local := onet.NewLocalTest(utils.SUITE)
	_, el, _ := local.GenTree(size, true)

	client := NewLattigoSMCClient(el.List[0], "0")
	seed := []byte{'l', 'a', 't', 't', 'i', 'g', 'o'}

	err := client.SendSetupQuery(el, true, false, false, 0, 0, 0, seed)
	if err != nil {
		t.Fatal(err)
		return
	}
	<-time.After(2 * time.Second)

	client1 := NewLattigoSMCClient(el.List[1], "1")

	q, err := client1.SendKeyRequest(true, false, false)
	log.Lvl1("Response of query : ", q)
	d1 := []byte{1, 2, 3, 4, 5, 6}
	queryID1, err := client1.SendWriteQuery(el, d1)
	if err != nil {
		t.Fatal("Could not start client :", err)

	}

	log.Lvl2("Query Id 1: ", queryID1)
	<-time.After(1 * time.Second)

	d2 := []byte{8, 9, 10, 11, 12, 13}
	queryID2, err := client1.SendWriteQuery(el, d2)
	if err != nil {
		t.Fatal("Could not start client :", err)

	}

	log.Lvl2("Query Id 2: ", queryID2)
	<-time.After(1 * time.Second)

	log.Lvl1("oWo Now wee sum up our senpai cipher owo ")

	resultSum, err := client1.SendSumQuery(*queryID1, *queryID2)
	log.Lvl1("Sum of ct1 and ct2 is stored in : ", resultSum)

	//Try to do a key switch on it!!!
	<-time.After(1 * time.Second)
	client2 := NewLattigoSMCClient(el.List[2], "2")
	dataSum, err := client2.GetPlaintext(el, &resultSum)
	log.Lvl1("Client retrieved data for sum : ", dataSum)

	resSum := make([]byte, 6)
	for i := range d1 {
		resSum[i] = d1[i] + d2[i]
	}

	assert.Equal(t, "Sum", dataSum[:6], resSum)

	return

}

func TestRelinearization(t *testing.T) {
	log.Lvl1("Testing relinearization")
	log.SetDebugVisible(1)
	size := 5
	local := onet.NewLocalTest(utils.SUITE)
	_, el, _ := local.GenTree(size, true)

	client := NewLattigoSMCClient(el.List[0], "0")
	seed := []byte{'l', 'a', 't', 't', 'i', 'g', 'o'}

	err := client.SendSetupQuery(el, true, true, false, 0, 0, 0, seed)
	if err != nil {
		t.Fatal(err)
		return
	}
	<-time.After(2 * time.Second)

	client1 := NewLattigoSMCClient(el.List[1], "1")

	q, err := client1.SendKeyRequest(true, false, false)
	log.Lvl1("Response of query : ", q)
	d1 := []byte{1, 2, 3, 4, 5, 6}
	queryID1, err := client1.SendWriteQuery(el, d1)
	if err != nil {
		t.Fatal("Could not start client :", err)

	}

	log.Lvl2("Query Id 1: ", queryID1)
	<-time.After(1 * time.Second)

	d2 := []byte{8, 9, 10, 11, 12, 13}
	queryID2, err := client1.SendWriteQuery(el, d2)
	if err != nil {
		t.Fatal("Could not start client :", err)

	}

	log.Lvl2("Query Id 2: ", queryID2)
	<-time.After(1 * time.Second)

	log.Lvl1("oWo Now wee sum up our senpai cipher owo ")

	result, err := client1.SendMultiplyQuery(*queryID1, *queryID2)
	log.Lvl1("Multiply of ct1 and ct2 is stored in : ", result)

	log.Lvl1("Requesting for relinearization!")
	result, err = client1.SendRelinQuery(result)

	//Try to do a key switch on it!!!
	<-time.After(1 * time.Second)
	client2 := NewLattigoSMCClient(el.List[2], "2")
	data, err := client2.GetPlaintext(el, &result)
	log.Lvl1("Client retrieved data for sum : ", data)

	res := make([]byte, 6)
	for i := range d1 {
		res[i] = d1[i] * d2[i]
	}

	assert.Equal(t, "Multiplication", data[:6], res)

}
