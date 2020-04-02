package service

import (
	"github.com/ldsec/lattigo/bfv"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"lattigo-smc/utils"
	"testing"
	"time"
)

const COEFFSIZE = 4096

func genTestLocalRoster(size int) *onet.Roster {
	local := onet.NewLocalTest(utils.SUITE)
	_, roster, _ := local.GenTree(size, true)
	return roster
}

func TestSetupPublicKeyGen(t *testing.T) {
	log.SetDebugVisible(3)
	log.Lvl1("Testing Setup with PublicKeyGeneration")

	size := 3
	paramsIdx := uint64(0)
	clientID := "ClientTestGenPK"
	roster := genTestLocalRoster(size)
	client := NewLattigoSMCClient(roster.List[1], clientID, paramsIdx)
	seed := []byte{'l', 'a', 't', 't', 'i', 'g', 'o'}

	err := client.SendSetupQuery(roster, true, false, false,
		0, 0, seed)

	if err != nil {
		t.Fatal("Setup Query returned error:", err)
	}
}

func TestSetupEvalKeyGen(t *testing.T) {
	log.SetDebugVisible(3)
	log.Lvl1("Testing Setup with EvalKeyGeneration")

	size := 3
	paramsIdx := uint64(0)
	clientID := "ClientTestGenEvK"
	roster := genTestLocalRoster(size)
	client := NewLattigoSMCClient(roster.List[1], clientID, paramsIdx)
	seed := []byte{'l', 'a', 't', 't', 'i', 'g', 'o'}

	err := client.SendSetupQuery(roster, false, true, false,
		0, 0, seed)

	if err != nil {
		t.Fatal("Setup Query returned error:", err)
	}
}

func TestSetupRotKeyGen(t *testing.T) {
	log.SetDebugVisible(3)
	log.Lvl1("Testing Setup with RotationKeyGeneration")

	size := 3
	paramsIdx := uint64(0)
	clientID := "ClientTestGenRtK"
	roster := genTestLocalRoster(size)
	client := NewLattigoSMCClient(roster.List[1], clientID, paramsIdx)
	seed := []byte{'l', 'a', 't', 't', 'i', 'g', 'o'}
	err := client.SendSetupQuery(roster, false, false, true,
		1, 0, seed)

	if err != nil {
		t.Fatal("Setup Query returned error:", err)
	}
}

// TODO: why is KeyQuery even needed?

// TODO: doesn't work. Modify client so as to use MasterPublicKey
func TestStore(t *testing.T) {
	log.SetDebugVisible(3)
	log.Lvl1("Testing Store")

	size := 3
	paramsIdx := uint64(0)
	clientID := "ClientTestStore"
	roster := genTestLocalRoster(size)
	client := NewLattigoSMCClient(roster.List[1], clientID, paramsIdx)
	seed := []byte{'l', 'a', 't', 't', 'i', 'g', 'o'}

	err := client.SendSetupQuery(roster, true, false, false,
		0, 0, seed)
	if err != nil {
		t.Fatal("Setup Query returned error:", err)
	}

	log.Lvl2("Setup Query succeeded")

	data := []uint64{0, 1, 2, 3, 4}
	CipherID, err := client.SendStoreQuery(data)
	if err != nil {
		t.Fatal("Store Query returned error:", err)
	}

	log.Lvl2("Store Query succeeded; new CipherID: ", CipherID)
}

/*
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
	q, _ := client1.SendKeyQuery(true, false, false, 0)
	<-time.After(200 * time.Millisecond)
	log.Lvl1("Reply of key request : ", q)
	content := []byte("lattigood")
	queryID, err := client1.SendStoreQuery(el, content)
	if err != nil {
		t.Fatal("Could not start client :", err)

	}

	log.Lvl2("Query Local Id : ", queryID, " with content : ", content)
	<-time.After(500 * time.Millisecond)

	//Client 2 now requests to switch the key for him...
	client2 := NewLattigoSMCClient(el.List[2], "2")
	data, err := client2.SendRetrieveQuery(queryID)
	log.Lvl1("Client retrieved data : ", data)

	assert.Equal(t, "Result", string(data[0:9]), string(content))

}
*/

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

	q, err := client1.SendKeyQuery(true, false, false, 0)
	log.Lvl1("Response of query : ", q)
	d1 := make([]byte, COEFFSIZE)
	n, err := rand.Read(d1)
	if err != nil || n != COEFFSIZE {
		t.Fatal(err, "could not initialize d1 ")
	}
	queryID1, err := client1.SendStoreQuery(el, d1)
	if err != nil {
		t.Fatal("Could not start client :", err)

	}

	log.Lvl2("Query Id 1: ", queryID1)
	<-time.After(1 * time.Second)

	d2 := make([]byte, COEFFSIZE)
	n, err = rand.Read(d2)
	if err != nil || n != COEFFSIZE {
		t.Fatal(err, "could not initialize d1 ")
	}

	queryID2, err := client1.SendStoreQuery(el, d2)
	if err != nil {
		t.Fatal("Could not start client :", err)

	}

	log.Lvl2("Query Id 2: ", queryID2)
	<-time.After(1 * time.Second)

	log.Lvl1("Suming up ciphers")

	resultSum, err := client1.SendSumQuery(*queryID1, *queryID2)
	log.Lvl1("Sum of ct1 and ct2 is stored in : ", resultSum)

	//Try to do a key switch on it!!!
	<-time.After(1 * time.Second)
	client2 := NewLattigoSMCClient(el.List[2], "2")
	dataSum, err := client2.SendRetrieveQuery(&resultSum)
	log.Lvl1("Client retrieved data for sum : ", dataSum)

	resSum := make([]byte, COEFFSIZE)
	for i := range d1 {
		resSum[i] = d1[i] + d2[i]
	}

	assert.Equal(t, "Sum", dataSum, resSum)

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

	q, err := client1.SendKeyQuery(true, false, false, 0)
	<-time.After(500 * time.Millisecond)
	log.Lvl1("Response of query : ", q)
	d1 := make([]byte, COEFFSIZE)
	n, err := rand.Read(d1)
	if err != nil || n != COEFFSIZE {
		t.Fatal(err, "could not initialize d1 ")
	}
	queryID1, err := client1.SendStoreQuery(el, d1)
	if err != nil {
		t.Fatal("Could not start client :", err)

	}

	log.Lvl2("Query Id 1: ", queryID1)
	<-time.After(1 * time.Second)

	d2 := make([]byte, COEFFSIZE)
	n, err = rand.Read(d2)
	if err != nil || n != COEFFSIZE {
		t.Fatal(err, "could not initialize d2 ")
	}

	queryID2, err := client1.SendStoreQuery(el, d2)
	if err != nil {
		t.Fatal("Could not start client :", err)

	}

	log.Lvl2("Query Id 2: ", queryID2)
	<-time.After(1 * time.Second)

	log.Lvl1("multiply up our ciphertexts")

	result, err := client1.SendMultiplyQuery(*queryID1, *queryID2)
	log.Lvl1("Multiply of ct1 and ct2 is stored in : ", result)

	log.Lvl1("Requesting for relinearization!")
	result, err = client1.SendRelinQuery(result)

	//Try to do a key switch on it!!!
	<-time.After(2 * time.Second)
	client2 := NewLattigoSMCClient(el.List[2], "2")
	data, err := client2.SendRetrieveQuery(&result)
	log.Lvl1("Client retrieved data for multiply : ", data)

	res := make([]byte, COEFFSIZE)
	for i := range d1 {
		res[i] = d1[i] * d2[i]
	}

	assert.Equal(t, "Multiplication", data, res)

}

func TestRefresh(t *testing.T) {
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
	q, _ := client1.SendKeyQuery(true, false, false, 0)
	<-time.After(200 * time.Millisecond)
	log.Lvl1("Reply of key request : ", q)
	content := []byte("lattigood")
	queryID, err := client1.SendStoreQuery(el, content)
	if err != nil {
		t.Fatal("Could not start client :", err)

	}

	log.Lvl2("Query Local Id : ", queryID, " with content : ", content)
	<-time.After(500 * time.Millisecond)

	//Now request for a refresh..
	log.Lvl1("Request for refresh.")
	result, err := client1.SendRefreshQuery(queryID)
	if err != nil {
		t.Fatal(err)
	}

	<-time.After(3 * time.Second)
	//Client 2 now requests to switch the key for him...
	client2 := NewLattigoSMCClient(el.List[2], "2")
	data, err := client2.SendRetrieveQuery(&result)
	log.Lvl1("Client retrieved data : ", data)

	assert.Equal(t, "Result", string(data[0:9]), string(content))

}

func TestRotation(t *testing.T) {
	log.SetDebugVisible(4)
	size := 5
	K := 2
	rotIdx := bfv.RotationLeft
	local := onet.NewLocalTest(utils.SUITE)
	_, el, _ := local.GenTree(size, true)

	client := NewLattigoSMCClient(el.List[0], "0")
	seed := []byte{'l', 'a', 't', 't', 'i', 'g', 'o'}

	err := client.SendSetupQuery(el, true, false, true, uint64(K), rotIdx, 0, seed)
	if err != nil {
		t.Fatal(err)
		return
	}
	<-time.After(2 * time.Second)

	client1 := NewLattigoSMCClient(el.List[1], "1")

	q, err := client1.SendKeyQuery(true, false, false, 0)
	log.Lvl1("Response of query : ", q)
	<-time.After(time.Second)
	data := make([]byte, COEFFSIZE)
	n, err := rand.Read(data)
	if err != nil || n != COEFFSIZE {
		t.Fatal(err, "could not initialize data ")
	}
	queryID1, err := client1.SendStoreQuery(el, data)
	if err != nil {
		t.Fatal("Could not start client :", err)

	}

	log.Lvl2("Query Id 1: ", queryID1)
	<-time.After(1 * time.Second)

	log.Lvl1("Rotation of cipher to the right of ", K, "k step")

	resultRot, err := client1.SendRotationQuery(*queryID1, uint64(K), rotIdx)
	log.Lvl1("Rotation is stored in : ", resultRot)

	//Try to do a key switch on it!!!
	<-time.After(1 * time.Second)
	client2 := NewLattigoSMCClient(el.List[2], "2")
	got, err := client2.SendRetrieveQuery(&resultRot)

	//We need to split it in two
	got1, got2 := got[:COEFFSIZE/2], got[COEFFSIZE/2:]
	data1, data2 := data[:COEFFSIZE/2], data[COEFFSIZE/2:]

	expected1 := make([]byte, COEFFSIZE/2)
	expected2 := make([]byte, COEFFSIZE/2)

	copy(expected1[:len(expected1)-K], data1[K:])
	copy(expected1[len(expected1)-K:], data1[:K])

	copy(expected2[:len(expected2)-K], data2[K:])
	copy(expected2[len(expected2)-K:], data2[:K])

	log.Lvl1("Expected data 1 is : ", expected1)
	log.Lvl1("Retrieve data 1 is : ", got1)

	log.Lvl1("Expected data 2 is : ", expected2)
	log.Lvl1("Retrieve data 2 is : ", got2)

	assert.Equal(t, "rotation part 1 ", got1, expected1)
	assert.Equal(t, "rotation part 2 ", got2, expected2)

	return
}
