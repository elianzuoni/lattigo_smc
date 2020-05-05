package service

import (
	"github.com/ldsec/lattigo/bfv"
	"github.com/ldsec/lattigo/ring"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"lattigo-smc/service/messages"
	"lattigo-smc/utils"
	"testing"
)

var testDefaultSeed = []byte("soreta")

// Utility functions

func genLocalTestRoster(size int) (*onet.Roster, *onet.LocalTest) {
	local := onet.NewLocalTest(utils.SUITE)
	_, roster, _ := local.GenTree(size, true)
	return roster, local
}

func testNewClientCreateSession(roster *onet.Roster, paramsIdx int, clientID string) (*Client, messages.SessionID, *bfv.PublicKey, error) {
	client := NewClient(roster.List[0], clientID, bfv.DefaultParams[paramsIdx])

	log.Lvl2(client, "Creating session")
	sid, pk, err := client.CreateSession(roster, testDefaultSeed)

	return client, sid, pk, err
}

func testNewClientBindToSession(roster *onet.Roster, srvIdx int, paramsIdx int, clientID string,
	sid messages.SessionID, mpk *bfv.PublicKey) (*Client, error) {
	client := NewClient(roster.List[srvIdx], clientID, bfv.DefaultParams[paramsIdx])

	log.Lvl2(client, "Binding to session")
	err := client.BindToSession(sid, mpk)

	return client, err
}

func testGenRandomPolys(paramsIdx int) (context *ring.Context, p *ring.Poly, q *ring.Poly, err error) {
	params := bfv.DefaultParams[paramsIdx]
	context, err = ring.NewContextWithParams(uint64(1<<params.LogN), []uint64{params.T})
	if err != nil {
		return
	}

	p = context.NewUniformPoly()
	q = context.NewUniformPoly()
	return
}

// Tests

func TestCreateSession(t *testing.T) {
	log.SetDebugVisible(3)
	log.Lvl1("Testing CreateSession")

	size := 3
	roster, localTest := genLocalTestRoster(size)
	paramsIdx := 0
	clientID := "TestCreateSession"

	defer localTest.CloseAll()

	// Create session

	log.Lvl2("Going to create new session. Should not return error")
	c, _, _, err := testNewClientCreateSession(roster, paramsIdx, clientID) // We don't use the session
	if err != nil {
		t.Fatal("Method CreateSession returned error:", err)
	}
	log.Lvl2(c, "Method CreateSession correctly returned no error")
}

func TestBindToSession(t *testing.T) {
	log.SetDebugVisible(3)
	log.Lvl1("Testing BindToSession")

	size := 3
	roster, localTest := genLocalTestRoster(size)
	paramsIdx := 0

	defer localTest.CloseAll()

	// Create first client, and create session

	client1ID := "TestBindToSession-1"
	// Client1, SessionID, publicKey
	log.Lvl2("Going to create new session. Should not return error")
	c1, sid, mpk, err := testNewClientCreateSession(roster, paramsIdx, client1ID)
	if err != nil {
		t.Fatal("Method CreateSession on Client 1 returned error:", err)
	}
	log.Lvl2("Method CreateSession on Client 2 correctly returned no error")

	// Create second client, and bind to that session

	client2ID := "TestBindToSession-2"
	log.Lvl2("Going to bind to session. Should not return error")
	c2, err := testNewClientBindToSession(roster, 1, paramsIdx, client2ID, sid, mpk)
	if err != nil {
		t.Fatal("Method BindToSession returned error:", err)
	}
	log.Lvl2(c2, "Method BindToSession correctly returned no error")

	// Try to re-create a session on c1: should return error because it is already bound

	log.Lvl2("Going to create new session on Client 1. Should return error")
	// Ignore SessionID and publicKey
	_, _, err = c1.CreateSession(roster, testDefaultSeed)
	if err == nil {
		t.Fatal("Second call to method CreateSession on Client 1 did not return error")
	}
	log.Lvl2("Second call to method CreateSession on Client 1 correctly returned error:", err)

	// Try to create a session on c2: should return error because it is already bound

	log.Lvl2("Going to create new session on Client 2. Should return error")
	// Ignore SessionID and publicKey
	_, _, err = c2.CreateSession(roster, testDefaultSeed)
	if err == nil {
		t.Fatal("Call to method CreateSession on Client 2 did not return error")
	}
	log.Lvl2("Call to CreateSession on Client 2 correctly returned error:", err)

	// Try to bind c1 to session: should return error because it is already bound

	log.Lvl2("Going to bind to session on Client 1. Should return error")
	err = c1.BindToSession(sid, mpk)
	if err == nil {
		t.Fatal("Call to method BindToSession on Client 1 did not return error")
	}
	log.Lvl2("Call to method BindToSession on Client 1 correctly returned error:", err)

	// Try to bind c2 to session: should return error because it is already bound

	log.Lvl2("Going to bind to session on Client 2. Should return error")
	err = c2.BindToSession(sid, mpk)
	if err == nil {
		t.Fatal("Call to method BindToSession on Client 2 did not return error")
	}
	log.Lvl2("Call to method BindToSession on Client 2 correctly returned error:", err)

	return
}

// TODO: don't return error in query handling?
func TestCloseSession(t *testing.T) {
	log.SetDebugVisible(3)
	log.Lvl1("Testing CloseSession")

	size := 3
	roster, localTest := genLocalTestRoster(size)
	paramsIdx := 0

	defer localTest.CloseAll()

	// Create first client, and create session

	client1ID := "TestCloseSession-1"
	log.Lvl2("Going to create new session on Client 1. Should not return error")
	// Client1, SessionID, publicKey
	c1, sid, mpk, err := testNewClientCreateSession(roster, paramsIdx, client1ID)
	if err != nil {
		t.Fatal("Method CreateSession on Client 1 returned error:", err)
	}
	log.Lvl2("Method CreateSession on Client 1 correctly returned no error")

	// Create second client, and bind to that session

	client2ID := "TestCloseSession-2"
	log.Lvl2("Going to bind to session on Client 2. Should not return error")
	c2, err := testNewClientBindToSession(roster, 1, paramsIdx, client2ID, sid, mpk)
	if err != nil {
		t.Fatal("Method BindToSession on Client 2 returned error:", err)
	}
	log.Lvl2("Method BindToSession on Client 2 correctly returned no error")

	// Close session from second client: should return no error (indifferent which of the two closes it)

	log.Lvl2("Going to close session on Client 2. Should not return error")
	err = c2.CloseSession()
	if err != nil {
		t.Fatal("Call to method CloseSession on Client 2 returned error:", err)
	}
	log.Lvl2("Method CloseSession on Client 2 correctly returned no error")

	// Close session from first client: should return error, not because it is unbound (it is actually bound),
	// but because the session is already closed (inspect the logged error).

	log.Lvl2("Going to close session on Client 1. Should return error")
	err = c1.CloseSession()
	if err == nil {
		t.Fatal("Call to method CloseSession on Client 1 returned no error")
	}
	log.Lvl2("Call to method CloseSession on Client 1 correctly returned error (IMPORTANT: INSPECT):", err)
}

func TestUnbindFromSession(t *testing.T) {
	log.SetDebugVisible(2)
	log.Lvl1("Testing UnbindFromSession")

	size := 3
	roster, localTest := genLocalTestRoster(size)
	paramsIdx := 0

	defer localTest.CloseAll()

	// Create first client, and create session

	client1ID := "TestUnbindFromSession-1"
	log.Lvl2("Going to create new session on Client 1. Should not return error")
	// Client1, SessionID, publicKey
	c1, sid, mpk, err := testNewClientCreateSession(roster, paramsIdx, client1ID)
	if err != nil {
		t.Fatal("Method CreateSession on Client 1 returned error:", err)
	}
	log.Lvl2("Method CreateSession on Client 2 correctly returned no error")

	// Create second client, and bind to that session

	client2ID := "TestUnbindFromSession-2"
	log.Lvl2("Going to bind to session on Client 2. Should not return error")
	c2, err := testNewClientBindToSession(roster, 1, paramsIdx, client2ID, sid, mpk)
	if err != nil {
		t.Fatal("Method BindToSession on Client 2 returned error:", err)
	}
	log.Lvl2("Method BindToSession on Client 2 correctly returned no error")

	// Close session from second client: should return no error (indifferent which of the two closes it)

	log.Lvl2("Going to close session on Client 2. Should not return error")
	err = c2.CloseSession()
	if err != nil {
		t.Fatal("Call to method CloseSession on Client 2 returned error:", err)
	}
	log.Lvl2("Method CloseSession on Client 2 correctly returned no error")

	// Close session from first client: should return error, not because it is unbound (it is actually bound),
	// but because the session is already closed (inspect the logged error).

	log.Lvl2("Going to close session on Client 1. Should return error")
	err = c1.CloseSession()
	if err == nil {
		t.Fatal("Call to method CloseSession on Client 1 returned no error")
	}
	log.Lvl2("Call to method CloseSession on Client 1 correctly returned error (IMPORTANT: INSPECT):", err)

	// Just unbind the first client. Should not return error

	log.Lvl2("Going to unbind from session on Client 1. Should not return error")
	err = c1.UnbindFromSession()
	if err != nil {
		t.Fatal("Call to method UnbindFromSession on Client 1 returned error:", err)
	}
	log.Lvl2("Call to method UnbindFromSession on Client 1 correctly returned no error")

	// Try unbinding again the first client. Should return error

	log.Lvl2("Going to unbind from session on Client 1, again. Should return error")
	err = c1.UnbindFromSession()
	if err == nil {
		t.Fatal("Second call to method UnbindFromSession on Client 1 returned no error")
	}
	log.Lvl2("Second call to method UnbindFromSession on Client 1 correctly returned error:", err)

	// Try unbinding the second client. Should return error

	log.Lvl2("Going to unbind from session on Client 2. Should return error")
	err = c2.UnbindFromSession()
	if err == nil {
		t.Fatal("Call to method UnbindFromSession on Client 2 returned no error")
	}
	log.Lvl2("Call to method UnbindFromSession on Client 2 correctly returned error:", err)

}

// TODO: prohibit second query server-side?
func TestGenEvalKeyQuery(t *testing.T) {
	log.SetDebugVisible(3)
	log.Lvl1("Testing GenEvalKeyQuery")

	size := 3
	roster, localTest := genLocalTestRoster(size)
	defer localTest.CloseAll()

	// Create session

	paramsIdx := 0
	clientID := "TestGenEvalKeyQuery"
	log.Lvl2("Going to create new session. Should not return error")
	c, _, _, err := testNewClientCreateSession(roster, paramsIdx, clientID) // We don't use the session
	if err != nil {
		t.Fatal("Method CreateSession returned error:", err)
	}
	log.Lvl2("Method CreateSession correctly returned no error")

	// Generate evaluation key

	log.Lvl2("Going to generate evaluation key. Should not return error")
	err = c.SendGenEvalKeyQuery(nil)
	if err != nil {
		t.Fatal("Method SendGenEvalKeyQuery returned error:", err)
	}
	log.Lvl2("Method SendGenEvalKeyQuery correctly returned no error")

	return
}

func TestGenRotKeyQuery(t *testing.T) {
	log.SetDebugVisible(3)
	log.Lvl1("Testing GenRotKeyQuery")

	size := 3
	roster, localTest := genLocalTestRoster(size)
	defer localTest.CloseAll()

	// Create session

	paramsIdx := 0
	clientID := "TestGenRotKeyQuery"
	log.Lvl2("Going to create new session. Should not return error")
	c, _, _, err := testNewClientCreateSession(roster, paramsIdx, clientID) // We don't use the session
	if err != nil {
		t.Fatal("Method CreateSession returned error:", err)
	}
	log.Lvl2("Method CreateSession correctly returned no error")

	// Generate rotation key

	log.Lvl2("Going to generate rotation key. Should not return error")
	rotIdx := 0
	k := uint64(1000)
	err = c.SendGenRotKeyQuery(rotIdx, k, nil)
	if err != nil {
		t.Fatal("Method SendGenRotKeyQuery returned error:", err)
	}
	log.Lvl2("Method SendGenRotKeyQuery correctly returned no error")

	return
}

func TestStoreRetrieveQuery(t *testing.T) {
	log.SetDebugVisible(3)
	log.Lvl1("Testing Store and Retrieve queries")

	size := 3
	roster, localTest := genLocalTestRoster(size)
	defer localTest.CloseAll()

	// Create session

	paramsIdx := 0
	clientID1 := "TestStoreRetrieve-1"
	log.Lvl2("Going to create new session. Should not return error")
	c1, sid, mpk, err := testNewClientCreateSession(roster, paramsIdx, clientID1)
	if err != nil {
		t.Fatal("Method CreateSession returned error:", err)
	}
	log.Lvl2("Method CreateSession correctly returned no error")

	// Generate data

	log.Lvl2("Going to generate random data. Should not return error")
	// We don't use the second polynomial and the context
	_, p, _, err := testGenRandomPolys(paramsIdx)
	if err != nil {
		t.Fatal("Could not generate random data:", err)
	}
	log.Lvl2("Successfully generated random data")

	// Store the data

	log.Lvl2("Going to store data. Should not return error")
	origData := p.Coeffs[0] // Only one modulus exists
	cid, err := c1.SendStoreQuery("a", origData)
	if err != nil {
		t.Fatal("Method SendStoreQuery returned error:", err)
	}
	log.Lvl2("Method SendStoreQuery correctly returned no error")

	// Create second client

	client2ID := "TestStoreRetrieve-2"
	log.Lvl2("Going to bind to session on Client 2. Should not return error")
	c2, err := testNewClientBindToSession(roster, 1, paramsIdx, client2ID, sid, mpk)
	if err != nil {
		t.Fatal("Method BindToSession on Client 2 returned error:", err)
	}
	log.Lvl2("Method BindToSession on Client 2 correctly returned no error")

	// Retrieve the data from second client

	log.Lvl2("Going to retrieve data from second client. Should not return error")
	retrData, err := c2.SendRetrieveQuery(cid)
	if err != nil {
		t.Fatal("Method SendRetrieveQuery returned error:", err)
	}
	log.Lvl2("Method SendRetrieveQuery correctly returned no error")

	// Test for equality

	log.Lvl2("Going to test for equality. Should be the same")
	if !utils.Equalslice(origData, retrData) {
		t.Fatal("Original data and retrieved data are not the same")
	}
	log.Lvl2("Original data and retrieved data are the same")

	return
}

func TestSumQuery(t *testing.T) {
	log.SetDebugVisible(3)
	log.Lvl1("Testing Sum query")

	size := 4
	roster, localTest := genLocalTestRoster(size)
	defer localTest.CloseAll()

	// Create session

	paramsIdx := 0
	clientID1 := "TestSumQuery-1"
	log.Lvl2("Going to create new session. Should not return error")
	c1, sid, mpk, err := testNewClientCreateSession(roster, paramsIdx, clientID1)
	if err != nil {
		t.Fatal("Method CreateSession returned error:", err)
	}
	log.Lvl2("Method CreateSession correctly returned no error")

	// Generate data

	log.Lvl2("Going to generate random data. Should not return error")
	ctx, p, q, err := testGenRandomPolys(paramsIdx)
	if err != nil {
		t.Fatal("Could not generate random data:", err)
	}
	log.Lvl2("Successfully generated random data")

	// Store the first vector from first client

	log.Lvl2("Going to store first vector. Should not return error")
	data1 := p.Coeffs[0] // Only one modulus exists
	cid1, err := c1.SendStoreQuery("a", data1)
	if err != nil {
		t.Fatal("Method SendStoreQuery for first vector returned error:", err)
	}
	log.Lvl2("Method SendStoreQuery for first vector correctly returned no error")

	// Create second client

	client2ID := "TestSumQuery-2"
	log.Lvl2("Going to bind to session on Client 2. Should not return error")
	c2, err := testNewClientBindToSession(roster, 1, paramsIdx, client2ID, sid, mpk)
	if err != nil {
		t.Fatal("Method BindToSession on Client 2 returned error:", err)
	}
	log.Lvl2("Method BindToSession on Client 2 correctly returned no error")

	// Store the second vector from second client

	log.Lvl2("Going to store second vector from second client. Should not return error")
	data2 := q.Coeffs[0] // Only one modulus exists
	cid2, err := c2.SendStoreQuery("b", data2)
	if err != nil {
		t.Fatal("Method SendStoreQuery for second vector returned error:", err)
	}
	log.Lvl2("Method SendStoreQuery for second vector correctly returned no error")

	// Create third client

	client3ID := "TestSumQuery-3"
	log.Lvl2("Going to bind to session on Client 3. Should not return error")
	c3, err := testNewClientBindToSession(roster, 2, paramsIdx, client3ID, sid, mpk)
	if err != nil {
		t.Fatal("Method BindToSession on Client 3 returned error:", err)
	}
	log.Lvl2("Method BindToSession on Client 3 correctly returned no error")

	// Sum the vectors remotely from third client

	log.Lvl2("Going to sum the two vectors remotely from third client. Should not return error")
	cidSum, err := c3.SendSumQuery(cid1, cid2)
	if err != nil {
		t.Fatal("Method SendSumQuery returned error:", err)
	}
	log.Lvl2("Method SendSumQuery correctly returned no error")

	// Sum the vectors locally

	sum := ctx.NewPoly()
	ctx.Add(p, q, sum)
	origSum := sum.Coeffs[0] // Only one modulus is present

	// Create fourth client

	client4ID := "TestSumQuery-4"
	log.Lvl2("Going to bind to session on Client 4. Should not return error")
	c4, err := testNewClientBindToSession(roster, 3, paramsIdx, client4ID, sid, mpk)
	if err != nil {
		t.Fatal("Method BindToSession on Client 4 returned error:", err)
	}
	log.Lvl2("Method BindToSession on Client 4 correctly returned no error")

	// Retrieve the remote sum from fourth client

	log.Lvl2("Going to retrieve the remote sum from fourth client. Should not return error")
	retrSum, err := c4.SendRetrieveQuery(cidSum)
	if err != nil {
		t.Fatal("Method SendRetrieveQuery returned error:", err)
	}
	log.Lvl2("Method SendRetrieveQuery correctly returned no error")

	// Test for equality

	log.Lvl2("Going to test for equality. Should be the same")
	if !utils.Equalslice(origSum, retrSum) {
		t.Fatal("Original sum and retrieved sum are not the same")
	}
	log.Lvl2("Original sum and retrieved sum are the same")

	return
}

func TestMultiplyRelinQuery(t *testing.T) {
	log.SetDebugVisible(3)
	log.Lvl1("Testing Multiply and Relin query")

	size := 5
	roster, localTest := genLocalTestRoster(size)
	defer localTest.CloseAll()

	// Create session

	paramsIdx := 1
	clientID1 := "TestMultiplyRelinQuery-1"
	log.Lvl2("Going to create new session. Should not return error")
	c1, sid, mpk, err := testNewClientCreateSession(roster, paramsIdx, clientID1)
	if err != nil {
		t.Fatal("Method CreateSession returned error:", err)
	}
	log.Lvl2("Method CreateSession correctly returned no error")

	// Generate evaluation key from first client

	log.Lvl2("Going to generate evaluation key. Should not return error")
	err = c1.SendGenEvalKeyQuery(nil)
	if err != nil {
		t.Fatal("Method SendGenEvalKeyQuery returned error:", err)
	}
	log.Lvl2("Method SendGenEvalKeyQuery correctly returned no error")

	// Generate data

	log.Lvl2("Going to generate random data. Should not return error")
	ctx, p, q, err := testGenRandomPolys(paramsIdx)
	if err != nil {
		t.Fatal("Could not generate random data:", err)
	}
	log.Lvl2("Successfully generated random data")

	// Store the first vector from first client

	log.Lvl2("Going to store first vector. Should not return error")
	data1 := p.Coeffs[0] // Only one modulus exists
	cid1, err := c1.SendStoreQuery("a", data1)
	if err != nil {
		t.Fatal("Method SendStoreQuery for first vector returned error:", err)
	}
	log.Lvl2("Method SendStoreQuery for first vector correctly returned no error")

	// Create second client

	client2ID := "TestMultiplyRelin-2"
	log.Lvl2("Going to bind to session on Client 2. Should not return error")
	c2, err := testNewClientBindToSession(roster, 1, paramsIdx, client2ID, sid, mpk)
	if err != nil {
		t.Fatal("Method BindToSession on Client 2 returned error:", err)
	}
	log.Lvl2("Method BindToSession on Client 2 correctly returned no error")

	// Store the second vector from second client

	log.Lvl2("Going to store second vector. Should not return error")
	data2 := q.Coeffs[0] // Only one modulus exists
	cid2, err := c2.SendStoreQuery("b", data2)
	if err != nil {
		t.Fatal("Method SendStoreQuery for second vector returned error:", err)
	}
	log.Lvl2("Method SendStoreQuery for second vector correctly returned no error")

	// Create third client

	client3ID := "TestMultiplyRelin-3"
	log.Lvl2("Going to bind to session on Client 3. Should not return error")
	c3, err := testNewClientBindToSession(roster, 2, paramsIdx, client3ID, sid, mpk)
	if err != nil {
		t.Fatal("Method BindToSession on Client 3 returned error:", err)
	}
	log.Lvl2("Method BindToSession on Client 3 correctly returned no error")

	// Multiply the vectors remotely from third client

	log.Lvl2("Going to multiply the two vectors remotely. Should not return error")
	cidMul, err := c3.SendMultiplyQuery(cid1, cid2)
	if err != nil {
		t.Fatal("Method SendMultiplyQuery returned error:", err)
	}
	log.Lvl2("Method SendMultiplyQuery correctly returned no error")

	// Create fourth client

	client4ID := "TestMultiplyRelin-4"
	log.Lvl2("Going to bind to session on Client 4. Should not return error")
	c4, err := testNewClientBindToSession(roster, 3, paramsIdx, client4ID, sid, mpk)
	if err != nil {
		t.Fatal("Method BindToSession on Client 4 returned error:", err)
	}
	log.Lvl2("Method BindToSession on Client 4 correctly returned no error")

	// Relinearise the remote product (remotely)

	log.Lvl2("Going to relinearise the remote product (remotely). Should not return error")
	cidMul, err = c4.SendRelinQuery(cidMul) // The CipherID changes
	if err != nil {
		t.Fatal("Method SendRelinQuery returned error:", err)
	}
	log.Lvl2("Method SendRelinQuery correctly returned no error")

	// Multiply the vectors locally

	mul := ctx.NewPoly()
	ctx.MulCoeffs(p, q, mul)
	origMul := mul.Coeffs[0] // Only one modulus is present

	// Create fifth client

	client5ID := "TestMultiplyRelin-5"
	log.Lvl2("Going to bind to session on Client 5. Should not return error")
	c5, err := testNewClientBindToSession(roster, 4, paramsIdx, client5ID, sid, mpk)
	if err != nil {
		t.Fatal("Method BindToSession on Client 5 returned error:", err)
	}
	log.Lvl2("Method BindToSession on Client 5 correctly returned no error")

	// Retrieve the remote product

	log.Lvl2("Going to retrieve the remote product. Should not return error")
	retrMul, err := c5.SendRetrieveQuery(cidMul)
	if err != nil {
		t.Fatal("Method SendRetrieveQuery returned error:", err)
	}
	log.Lvl2("Method SendRetrieveQuery correctly returned no error")

	// Test for equality

	log.Lvl2("Going to test for equality. Should be the same")
	if !utils.Equalslice(origMul, retrMul) {
		t.Fatal("Original product and retrieved product are not the same")
	}
	log.Lvl2("Original product and retrieved product are the same")

	return
}

// To make the refresh test meaningful, a moderately complex circuit is evaluated, then the final value is refreshed.
// Interestingly, it only works with paramsIdx >= 1 (in which case, it doesn't even need refreshing).
// Specifically, what's done is the following:
// a, b <-$ random
// ab <- Mul(a, b)
// ab <- Relin(ab)
// c, d <-$ random
// cd <- Mul(c, d)
// cd <- Relin(cd)
// abcd <- Mul(ab, cd)
// abcd <- Relin(abcd)
func TestRefreshQuery(t *testing.T) {
	log.SetDebugVisible(3)
	log.Lvl1("Testing Refresh query")

	size := 4
	roster, localTest := genLocalTestRoster(size)
	defer localTest.CloseAll()

	// Create session

	paramsIdx := 1
	clientID1 := "TestRefreshQuery-1"
	log.Lvl2("Going to create new session. Should not return error")
	client1, sid, mpk, err := testNewClientCreateSession(roster, paramsIdx, clientID1)
	if err != nil {
		t.Fatal("Method CreateSession returned error:", err)
	}
	log.Lvl2("Method CreateSession correctly returned no error")

	// Generate evaluation key from first client

	log.Lvl2("Going to generate evaluation key. Should not return error")
	err = client1.SendGenEvalKeyQuery(nil)
	if err != nil {
		t.Fatal("Method SendGenEvalKeyQuery returned error:", err)
	}
	log.Lvl2("Method SendGenEvalKeyQuery correctly returned no error")

	// Generate a and b

	log.Lvl2("Going to generate a and b. Should not return error")
	ctx, a, b, err := testGenRandomPolys(paramsIdx)
	if err != nil {
		t.Fatal("Could not generate a and b:", err)
	}
	log.Lvl2("Successfully generated a and b")

	// Store a from first client

	log.Lvl2("Going to store \"a\". Should not return error")
	cidA, err := client1.SendStoreQuery("a", a.Coeffs[0]) // Only one modulus exists
	if err != nil {
		t.Fatal("Method SendStoreQuery for \"a\" returned error:", err)
	}
	log.Lvl2("Method SendStoreQuery for \"a\" correctly returned no error")

	// Create second client

	client2ID := "TestRefreshQuery-2"
	log.Lvl2("Going to bind to session on Client 2. Should not return error")
	client2, err := testNewClientBindToSession(roster, 1, paramsIdx, client2ID, sid, mpk)
	if err != nil {
		t.Fatal("Method BindToSession on Client 2 returned error:", err)
	}
	log.Lvl2("Method BindToSession on Client 2 correctly returned no error")

	// Store b from second client

	log.Lvl2("Going to store \"b\". Should not return error")
	cidB, err := client2.SendStoreQuery("b", b.Coeffs[0]) // Only one modulus exists
	if err != nil {
		t.Fatal("Method SendStoreQuery for \"b\" returned error:", err)
	}
	log.Lvl2("Method SendStoreQuery for \"b\" correctly returned no error")

	// Multiply a and b remotely from first client

	log.Lvl2("Going to multiply \"a\" and \"b\" remotely. Should not return error")
	cidAB, err := client1.SendMultiplyQuery(cidA, cidB)
	if err != nil {
		t.Fatal("Method SendMultiplyQuery for\"a\" and \"b\" returned error:", err)
	}
	log.Lvl2("Method SendMultiplyQuery for \"a\" and \"b\" correctly returned no error")

	// Relinearise the remote ab (remotely) from the second client

	log.Lvl2("Going to relinearise \"ab\" (remotely). Should not return error")
	cidAB, err = client2.SendRelinQuery(cidAB) // The CipherID changes
	if err != nil {
		t.Fatal("Method SendRelinQuery for \"ab\" returned error:", err)
	}
	log.Lvl2("Method SendRelinQuery for \"ab\" correctly returned no error")

	// Refresh the remote ab from the first client

	log.Lvl2("Going to refresh \"ab\" (remotely). Should not return error")
	cidAB, err = client1.SendRefreshQuery(cidAB, nil) // The CipherID changes
	if err != nil {
		t.Fatal("Method SendRefreshQuery for \"ab\" returned error:", err)
	}
	log.Lvl2("Method SendRefreshQuery for \"ab\" correctly returned no error")

	// Multiply a and b locally

	ab := ctx.NewPoly()
	ctx.MulCoeffs(a, b, ab)

	// Generate c and d

	log.Lvl2("Going to generate c and d. Should not return error")
	ctx, c, d, err := testGenRandomPolys(paramsIdx)
	if err != nil {
		t.Fatal("Could not generate c and d:", err)
	}
	log.Lvl2("Successfully generated c and d")

	// Create third client

	client3ID := "TestRefreshQuery-3"
	log.Lvl2("Going to bind to session on Client 3. Should not return error")
	client3, err := testNewClientBindToSession(roster, 2, paramsIdx, client3ID, sid, mpk)
	if err != nil {
		t.Fatal("Method BindToSession on Client 3 returned error:", err)
	}
	log.Lvl2("Method BindToSession on Client 3 correctly returned no error")

	// Store c from third client

	log.Lvl2("Going to store \"c\". Should not return error")
	cidC, err := client3.SendStoreQuery("c", c.Coeffs[0]) // Only one modulus exists
	if err != nil {
		t.Fatal("Method SendStoreQuery for \"c\" returned error:", err)
	}
	log.Lvl2("Method SendStoreQuery for \"c\" correctly returned no error")

	// Create fourth client

	client4ID := "TestRotationQuery-4"
	log.Lvl2("Going to bind to session on Client 4. Should not return error")
	client4, err := testNewClientBindToSession(roster, 3, paramsIdx, client4ID, sid, mpk)
	if err != nil {
		t.Fatal("Method BindToSession on Client 4 returned error:", err)
	}
	log.Lvl2("Method BindToSession on Client 4 correctly returned no error")

	// Store d from the fourth client

	log.Lvl2("Going to store \"d\". Should not return error")
	cidD, err := client4.SendStoreQuery("d", d.Coeffs[0]) // Only one modulus exists
	if err != nil {
		t.Fatal("Method SendStoreQuery for \"d\" returned error:", err)
	}
	log.Lvl2("Method SendStoreQuery for \"d\" correctly returned no error")

	// Multiply c and d remotely from the third client

	log.Lvl2("Going to multiply \"c\" and \"d\" remotely. Should not return error")
	cidCD, err := client3.SendMultiplyQuery(cidC, cidD)
	if err != nil {
		t.Fatal("Method SendMultiplyQuery for\"c\" and \"d\" returned error:", err)
	}
	log.Lvl2("Method SendMultiplyQuery for \"c\" and \"d\" correctly returned no error")

	// Relinearise the remote cd (remotely) from the fourth client

	log.Lvl2("Going to relinearise \"cd\" (remotely). Should not return error")
	cidCD, err = client4.SendRelinQuery(cidCD) // The CipherID changes
	if err != nil {
		t.Fatal("Method SendRelinQuery for \"cd\" returned error:", err)
	}
	log.Lvl2("Method SendRelinQuery for \"cd\" correctly returned no error")

	// Refresh the remote cd from the third client

	log.Lvl2("Going to refresh \"cd\" (remotely). Should not return error")
	cidCD, err = client3.SendRefreshQuery(cidCD, nil) // The CipherID changes
	if err != nil {
		t.Fatal("Method SendRefreshQuery for \"cd\" returned error:", err)
	}
	log.Lvl2("Method SendRefreshQuery for \"cd\" correctly returned no error")

	// Multiply c and d locally

	cd := ctx.NewPoly()
	ctx.MulCoeffs(c, d, cd)

	// Multiply ab and cd remotely from first client

	log.Lvl2("Going to multiply \"ab\" and \"cd\" remotely. Should not return error")
	cidABCD, err := client1.SendMultiplyQuery(cidAB, cidCD)
	if err != nil {
		t.Fatal("Method SendMultiplyQuery for\"ab\" and \"cd\" returned error:", err)
	}
	log.Lvl2("Method SendMultiplyQuery for \"ab\" and \"cd\" correctly returned no error")

	// Relinearise the remote abcd (remotely) from fourth client

	log.Lvl2("Going to relinearise \"abcd\" (remotely). Should not return error")
	cidABCD, err = client4.SendRelinQuery(cidABCD) // The CipherID changes
	if err != nil {
		t.Fatal("Method SendRelinQuery for \"abcd\" returned error:", err)
	}
	log.Lvl2("Method SendRelinQuery for \"abcd\" correctly returned no error")

	// Refresh the remote abcd from second client

	log.Lvl2("Going to refresh \"abcd\" (remotely). Should not return error")
	cidABCD, err = client2.SendRefreshQuery(cidABCD, nil) // The CipherID changes
	if err != nil {
		t.Fatal("Method SendRefreshQuery for \"abcd\" returned error:", err)
	}
	log.Lvl2("Method SendRefreshQuery for \"abcd\" correctly returned no error")

	// Multiply ab and cd locally

	abcd := ctx.NewPoly()
	ctx.MulCoeffs(ab, cd, abcd)

	// Retrieve the remote abcd from third client

	log.Lvl2("Going to retrieve the remote \"abcd\". Should not return error")
	retr, err := client3.SendRetrieveQuery(cidABCD)
	if err != nil {
		t.Fatal("Method SendRetrieveQuery for \"abcd\" returned error:", err)
	}
	log.Lvl2("Method SendRetrieveQuery for \"abcd\" correctly returned no error")

	// Test for equality

	log.Lvl2("Going to test for equality. Should be the same")
	if !utils.Equalslice(abcd.Coeffs[0], retr) {
		t.Fatal("Original \"abcd\" and retrieved \"abcd\" are not the same")
	}
	log.Lvl2("Original \"abcd\" and retrieved \"abcd\" are the same")

	return
}

func TestRotationQuery(t *testing.T) {
	log.SetDebugVisible(3)
	log.Lvl1("Testing Rotation query")

	size := 5
	roster, localTest := genLocalTestRoster(size)
	defer localTest.CloseAll()

	// Create session

	paramsIdx := 0
	clientID1 := "TestRotationQuery-1"
	log.Lvl2("Going to create new session. Should not return error")
	c1, sid, mpk, err := testNewClientCreateSession(roster, paramsIdx, clientID1)
	if err != nil {
		t.Fatal("Method CreateSession returned error:", err)
	}
	log.Lvl2("Method CreateSession correctly returned no error")

	// Generate rotation key from first client

	log.Lvl2("Going to generate first rotation key. Should not return error")
	rotIdx := bfv.RotationRight
	k := uint64(770)
	err = c1.SendGenRotKeyQuery(rotIdx, k, nil)
	if err != nil {
		t.Fatal("First call to method SendGenRotKeyQuery returned error:", err)
	}
	log.Lvl2("First call to method SendGenRotKeyQuery correctly returned no error")

	// TODO: allow for multiple rotation key generations

	// Generate data

	log.Lvl2("Going to generate random data. Should not return error")
	_, p, _, err := testGenRandomPolys(paramsIdx) // We only use one vector
	if err != nil {
		t.Fatal("Could not generate random data:", err)
	}
	log.Lvl2("Successfully generated random data")

	// Create third client

	client3ID := "TestRotationQuery-3"
	log.Lvl2("Going to bind to session on Client 3. Should not return error")
	c3, err := testNewClientBindToSession(roster, 2, paramsIdx, client3ID, sid, mpk)
	if err != nil {
		t.Fatal("Method BindToSession on Client 3 returned error:", err)
	}
	log.Lvl2("Method BindToSession on Client 3 correctly returned no error")

	// Store the vector from third client

	log.Lvl2("Going to store vector. Should not return error")
	data := p.Coeffs[0] // Only one modulus exists
	cid, err := c3.SendStoreQuery("a", data)
	if err != nil {
		t.Fatal("Method SendStoreQuery returned error:", err)
	}
	log.Lvl2("Method SendStoreQuery correctly returned no error")

	// Create fourth client

	client4ID := "TestRotationQuery-4"
	log.Lvl2("Going to bind to session on Client 4. Should not return error")
	c4, err := testNewClientBindToSession(roster, 3, paramsIdx, client4ID, sid, mpk)
	if err != nil {
		t.Fatal("Method BindToSession on Client 4 returned error:", err)
	}
	log.Lvl2("Method BindToSession on Client 4 correctly returned no error")

	// Rotate the vector remotely from the fourth client

	log.Lvl2("Going to rotate the vector remotely with the first key. Should not return error")
	cidRot, err := c4.SendRotationQuery(cid, rotIdx, k)
	if err != nil {
		t.Fatal("First call to method SendRotationQuery returned error:", err)
	}
	log.Lvl2("Call to method SendRotationQuery correctly returned no error")

	// Rotate the vector locally

	dataRot := make([]uint64, len(data))
	// Rotate first row
	row := data[:len(data)/2]
	rowRot := dataRot[:len(dataRot)/2]
	for i := range row {
		// Rotation to the right
		j := (i - int(k) + len(row)) % len(row)
		rowRot[i] = row[j]
	}
	// Rotate second row
	row = data[len(data)/2:]
	rowRot = dataRot[len(dataRot)/2:]
	for i := range row {
		// Rotation to the right
		j := (i - int(k) + len(row)) % len(row)
		rowRot[i] = row[j]
	}

	// Create fifth client

	client5ID := "TestRotationQuery-5"
	log.Lvl2("Going to bind to session on Client 5. Should not return error")
	c5, err := testNewClientBindToSession(roster, 4, paramsIdx, client5ID, sid, mpk)
	if err != nil {
		t.Fatal("Method BindToSession on Client 5 returned error:", err)
	}
	log.Lvl2("Method BindToSession on Client 5 correctly returned no error")

	// Retrieve the rotated ciphertext from fifth client

	log.Lvl2("Going to retrieve the remote rotated vector. Should not return error")
	var retrRot []uint64
	retrRot, err = c5.SendRetrieveQuery(cidRot)
	if err != nil {
		t.Fatal("Method SendRetrieveQuery returned error:", err)
	}
	log.Lvl2("Method SendRetrieveQuery correctly returned no error")

	// Test for equality

	log.Lvl2("Going to test for equality. Should be the same")
	if !utils.Equalslice(dataRot, retrRot) {
		t.Fatal("Original rotated vector and retrieved rotated vector are not the same")
	}
	log.Lvl2("Original rotated vector and retrieved rotated vector are the same")

	return
}

// The same circuit is evaluated, but with enc-shares-enc instead of refresh
func TestEncSharesQuery(t *testing.T) {
	log.SetDebugVisible(3)
	log.Lvl1("Testing enc-to-shares and shares-to-enc query")

	size := 4
	roster, localTest := genLocalTestRoster(size)
	defer localTest.CloseAll()

	// Create session

	paramsIdx := 1
	clientID1 := "TestEncSharesQuery-1"
	log.Lvl2("Going to create new session. Should not return error")
	client1, sid, mpk, err := testNewClientCreateSession(roster, paramsIdx, clientID1)
	if err != nil {
		t.Fatal("Method CreateSession returned error:", err)
	}
	log.Lvl2("Method CreateSession correctly returned no error")

	// Generate evaluation key from first client

	log.Lvl2("Going to generate evaluation key. Should not return error")
	err = client1.SendGenEvalKeyQuery(nil)
	if err != nil {
		t.Fatal("Method SendGenEvalKeyQuery returned error:", err)
	}
	log.Lvl2("Method SendGenEvalKeyQuery correctly returned no error")

	// Generate a and b

	log.Lvl2("Going to generate a and b. Should not return error")
	ctx, a, b, err := testGenRandomPolys(paramsIdx)
	if err != nil {
		t.Fatal("Could not generate a and b:", err)
	}
	log.Lvl2("Successfully generated a and b")

	// Store a from first client

	log.Lvl2("Going to store \"a\". Should not return error")
	cidA, err := client1.SendStoreQuery("a", a.Coeffs[0]) // Only one modulus exists
	if err != nil {
		t.Fatal("Method SendStoreQuery for \"a\" returned error:", err)
	}
	log.Lvl2("Method SendStoreQuery for \"a\" correctly returned no error")

	// Create second client

	client2ID := "TestEncSharesQuery-2"
	log.Lvl2("Going to bind to session on Client 2. Should not return error")
	client2, err := testNewClientBindToSession(roster, 1, paramsIdx, client2ID, sid, mpk)
	if err != nil {
		t.Fatal("Method BindToSession on Client 2 returned error:", err)
	}
	log.Lvl2("Method BindToSession on Client 2 correctly returned no error")

	// Store b from second client

	log.Lvl2("Going to store \"b\". Should not return error")
	cidB, err := client2.SendStoreQuery("b", b.Coeffs[0]) // Only one modulus exists
	if err != nil {
		t.Fatal("Method SendStoreQuery for \"b\" returned error:", err)
	}
	log.Lvl2("Method SendStoreQuery for \"b\" correctly returned no error")

	// Multiply a and b remotely from first client

	log.Lvl2("Going to multiply \"a\" and \"b\" remotely. Should not return error")
	cidAB, err := client1.SendMultiplyQuery(cidA, cidB)
	if err != nil {
		t.Fatal("Method SendMultiplyQuery for\"a\" and \"b\" returned error:", err)
	}
	log.Lvl2("Method SendMultiplyQuery for \"a\" and \"b\" correctly returned no error")

	// Relinearise the remote ab (remotely) from first client

	log.Lvl2("Going to relinearise \"ab\" (remotely). Should not return error")
	cidAB, err = client1.SendRelinQuery(cidAB) // The CipherID changes
	if err != nil {
		t.Fatal("Method SendRelinQuery for \"ab\" returned error:", err)
	}
	log.Lvl2("Method SendRelinQuery for \"ab\" correctly returned no error")

	// Share the remote ab from second client

	log.Lvl2("Going to share \"ab\" (remotely). Should not return error")
	shidAB, err := client2.SendEncToSharesQuery(cidAB)
	if err != nil {
		t.Fatal("Method SendRefreshQuery for \"ab\" returned error:", err)
	}
	log.Lvl2("Method SendEncToSharesQuery for \"ab\" correctly returned no error")

	// Re-encrypt the remote ab from first client

	log.Lvl2("Going to re-encrypt \"ab\" (remotely). Should not return error")
	cidAB, err = client1.SendSharesToEncQuery(shidAB, nil) // The CipherID changes
	if err != nil {
		t.Fatal("Method SendRefreshQuery for \"ab\" returned error:", err)
	}
	log.Lvl2("Method SendSharesToEncQuery for \"ab\" correctly returned no error")

	// Multiply a and b locally

	ab := ctx.NewPoly()
	ctx.MulCoeffs(a, b, ab)

	// Generate c and d

	log.Lvl2("Going to generate c and d. Should not return error")
	ctx, c, d, err := testGenRandomPolys(paramsIdx)
	if err != nil {
		t.Fatal("Could not generate c and d:", err)
	}
	log.Lvl2("Successfully generated c and d")

	// Create third client

	client3ID := "TestEncSharesQuery-3"
	log.Lvl2("Going to bind to session on Client 3. Should not return error")
	client3, err := testNewClientBindToSession(roster, 2, paramsIdx, client3ID, sid, mpk)
	if err != nil {
		t.Fatal("Method BindToSession on Client 3 returned error:", err)
	}
	log.Lvl2("Method BindToSession on Client 3 correctly returned no error")

	// Store c fro third client

	log.Lvl2("Going to store \"c\". Should not return error")
	cidC, err := client3.SendStoreQuery("c", c.Coeffs[0]) // Only one modulus exists
	if err != nil {
		t.Fatal("Method SendStoreQuery for \"c\" returned error:", err)
	}
	log.Lvl2("Method SendStoreQuery for \"c\" correctly returned no error")

	// Create fourth client

	client4ID := "TestEncSharesQuery-4"
	log.Lvl2("Going to bind to session on Client 4. Should not return error")
	client4, err := testNewClientBindToSession(roster, 3, paramsIdx, client4ID, sid, mpk)
	if err != nil {
		t.Fatal("Method BindToSession on Client 4 returned error:", err)
	}
	log.Lvl2("Method BindToSession on Client 4 correctly returned no error")

	// Store d from fourth client

	log.Lvl2("Going to store \"d\". Should not return error")
	cidD, err := client4.SendStoreQuery("d", d.Coeffs[0]) // Only one modulus exists
	if err != nil {
		t.Fatal("Method SendStoreQuery for \"d\" returned error:", err)
	}
	log.Lvl2("Method SendStoreQuery for \"d\" correctly returned no error")

	// Multiply c and d remotely from third client

	log.Lvl2("Going to multiply \"c\" and \"d\" remotely. Should not return error")
	cidCD, err := client3.SendMultiplyQuery(cidC, cidD)
	if err != nil {
		t.Fatal("Method SendMultiplyQuery for\"c\" and \"d\" returned error:", err)
	}
	log.Lvl2("Method SendMultiplyQuery for \"c\" and \"d\" correctly returned no error")

	// Relinearise the remote cd (remotely) from third client

	log.Lvl2("Going to relinearise \"cd\" (remotely). Should not return error")
	cidCD, err = client3.SendRelinQuery(cidCD) // The CipherID changes
	if err != nil {
		t.Fatal("Method SendRelinQuery for \"cd\" returned error:", err)
	}
	log.Lvl2("Method SendRelinQuery for \"cd\" correctly returned no error")

	// Share the remote cd from third client

	log.Lvl2("Going to share \"cd\" (remotely). Should not return error")
	shidCD, err := client3.SendEncToSharesQuery(cidCD)
	if err != nil {
		t.Fatal("Method SendRefreshQuery for \"ab\" returned error:", err)
	}
	log.Lvl2("Method SendEncToSharesQuery for \"cd\" correctly returned no error")

	// Re-encrypt the remote cd from the fourth client

	log.Lvl2("Going to re-encrypt \"cd\" (remotely). Should not return error")
	cidCD, err = client4.SendSharesToEncQuery(shidCD, nil) // The CipherID changes
	if err != nil {
		t.Fatal("Method SendRefreshQuery for \"ab\" returned error:", err)
	}
	log.Lvl2("Method SendSharesToEncQuery for \"cd\" correctly returned no error")

	// Multiply c and d locally

	cd := ctx.NewPoly()
	ctx.MulCoeffs(c, d, cd)

	// Multiply ab and cd remotely from first client

	log.Lvl2("Going to multiply \"ab\" and \"cd\" remotely. Should not return error")
	cidABCD, err := client1.SendMultiplyQuery(cidAB, cidCD)
	if err != nil {
		t.Fatal("Method SendMultiplyQuery for\"ab\" and \"cd\" returned error:", err)
	}
	log.Lvl2("Method SendMultiplyQuery for \"ab\" and \"cd\" correctly returned no error")

	// Relinearise the remote abcd (remotely) from first client

	log.Lvl2("Going to relinearise \"abcd\" (remotely). Should not return error")
	cidABCD, err = client1.SendRelinQuery(cidABCD) // The CipherID changes
	if err != nil {
		t.Fatal("Method SendRelinQuery for \"abcd\" returned error:", err)
	}
	log.Lvl2("Method SendRelinQuery for \"abcd\" correctly returned no error")

	// Share the remote abcd from first client

	log.Lvl2("Going to share \"abcd\" (remotely). Should not return error")
	shidABCD, err := client1.SendEncToSharesQuery(cidABCD)
	if err != nil {
		t.Fatal("Method SendRefreshQuery for \"ab\" returned error:", err)
	}
	log.Lvl2("Method SendEncToSharesQuery for \"abcd\" correctly returned no error")

	// Re-encrypt the remote abcd from fourth client

	log.Lvl2("Going to re-encrypt \"abcd\" (remotely). Should not return error")
	cidABCD, err = client4.SendSharesToEncQuery(shidABCD, nil) // The CipherID changes
	if err != nil {
		t.Fatal("Method SendRefreshQuery for \"ab\" returned error:", err)
	}
	log.Lvl2("Method SendSharesToEncQuery for \"abcd\" correctly returned no error")

	// Multiply ab and cd locally

	abcd := ctx.NewPoly()
	ctx.MulCoeffs(ab, cd, abcd)

	// Retrieve the remote abcd from second client

	log.Lvl2("Going to retrieve the remote \"abcd\". Should not return error")
	retr, err := client2.SendRetrieveQuery(cidABCD)
	if err != nil {
		t.Fatal("Method SendRetrieveQuery for \"abcd\" returned error:", err)
	}
	log.Lvl2("Method SendRetrieveQuery for \"abcd\" correctly returned no error")

	// Test for equality

	log.Lvl2("Going to test for equality. Should be the same")
	if !utils.Equalslice(abcd.Coeffs[0], retr) {
		t.Fatal("Original \"abcd\" and retrieved \"abcd\" are not the same")
	}
	log.Lvl2("Original \"abcd\" and retrieved \"abcd\" are the same")

	return
}
