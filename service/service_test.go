package service

import (
	"github.com/ldsec/lattigo/bfv"
	"github.com/ldsec/lattigo/ring"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"lattigo-smc/utils"
	"testing"
)

// var testCoeffSize = 4096
var testDefaultSeed = []byte("soreta")

// Utility functions

func genLocalTestRoster(size int) *onet.Roster {
	local := onet.NewLocalTest(utils.SUITE)
	_, roster, _ := local.GenTree(size, true)
	return roster
}

func testNewClientCreateSession(roster *onet.Roster, paramsIdx int, clientID string) (*Client, SessionID, *bfv.PublicKey, error) {
	client := NewClient(roster.List[0], clientID, paramsIdx)

	log.Lvl2(client, "Creating session")
	sid, pk, err := client.CreateSession(roster, testDefaultSeed)

	return client, sid, pk, err
}

func testNewClientBindToSession(roster *onet.Roster, paramsIdx int, clientID string, sid SessionID, mpk *bfv.PublicKey) (*Client, error) {
	client := NewClient(roster.List[1], clientID, paramsIdx)

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
	roster := genLocalTestRoster(size)
	paramsIdx := 0
	clientID := "TestCreateSession"

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
	roster := genLocalTestRoster(size)
	paramsIdx := 0

	// Create first client, and create session

	client1ID := "TestBindToSession-1"
	// Client1, SessionID, MasterPublicKey
	log.Lvl2("Going to create new session. Should not return error")
	c1, sid, mpk, err := testNewClientCreateSession(roster, paramsIdx, client1ID)
	if err != nil {
		t.Fatal("Method CreateSession on Client 1 returned error:", err)
	}
	log.Lvl2("Method CreateSession on Client 2 correctly returned no error")

	// Create second client, and bind to that session

	client2ID := "TestBindToSession-2"
	log.Lvl2("Going to bind to session. Should not return error")
	c2, err := testNewClientBindToSession(roster, paramsIdx, client2ID, sid, mpk)
	if err != nil {
		t.Fatal("Method BindToSession returned error:", err)
	}
	log.Lvl2(c2, "Method BindToSession correctly returned no error")

	// Try to re-create a session on c1: should return error because it is already bound

	log.Lvl2("Going to create new session on Client 1. Should return error")
	// Ignore SessionID and MasterPublicKey
	_, _, err = c1.CreateSession(roster, testDefaultSeed)
	if err == nil {
		t.Fatal("Second call to method CreateSession on Client 1 did not return error")
	}
	log.Lvl2("Second call to method CreateSession on Client 1 correctly returned error:", err)

	// Try to create a session on c2: should return error because it is already bound

	log.Lvl2("Going to create new session on Client 2. Should return error")
	// Ignore SessionID and MasterPublicKey
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
	roster := genLocalTestRoster(size)
	paramsIdx := 0

	// Create first client, and create session

	client1ID := "TestCloseSession-1"
	log.Lvl2("Going to create new session on Client 1. Should not return error")
	// Client1, SessionID, MasterPublicKey
	c1, sid, mpk, err := testNewClientCreateSession(roster, paramsIdx, client1ID)
	if err != nil {
		t.Fatal("Method CreateSession on Client 1 returned error:", err)
	}
	log.Lvl2("Method CreateSession on Client 1 correctly returned no error")

	// Create second client, and bind to that session

	client2ID := "TestCloseSession-2"
	log.Lvl2("Going to bind to session on Client 2. Should not return error")
	c2, err := testNewClientBindToSession(roster, paramsIdx, client2ID, sid, mpk)
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
	roster := genLocalTestRoster(size)
	paramsIdx := 0

	// Create first client, and create session

	client1ID := "TestUnbindFromSession-1"
	log.Lvl2("Going to create new session on Client 1. Should not return error")
	// Client1, SessionID, MasterPublicKey
	c1, sid, mpk, err := testNewClientCreateSession(roster, paramsIdx, client1ID)
	if err != nil {
		t.Fatal("Method CreateSession on Client 1 returned error:", err)
	}
	log.Lvl2("Method CreateSession on Client 2 correctly returned no error")

	// Create second client, and bind to that session

	client2ID := "TestUnbindFromSession-2"
	log.Lvl2("Going to bind to session on Client 2. Should not return error")
	c2, err := testNewClientBindToSession(roster, paramsIdx, client2ID, sid, mpk)
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
	roster := genLocalTestRoster(size)

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
	err = c.SendGenEvalKeyQuery()
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
	roster := genLocalTestRoster(size)

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
	err = c.SendGenRotKeyQuery(rotIdx, k)
	if err != nil {
		t.Fatal("Method SendGenRotKeyQuery returned error:", err)
	}
	log.Lvl2("Method SendGenRotKeyQuery correctly returned no error")

	return
}

// TODO: why is KeyQuery even needed?

func TestStoreRetrieveQuery(t *testing.T) {
	log.SetDebugVisible(4)
	log.Lvl1("Testing Store and Retrieve queries")

	size := 3
	roster := genLocalTestRoster(size)

	// Create session

	paramsIdx := 0
	clientID := "TestStoreRetrieve"
	log.Lvl2("Going to create new session. Should not return error")
	c, _, _, err := testNewClientCreateSession(roster, paramsIdx, clientID) // We don't use the session
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
	cid, err := c.SendStoreQuery(origData)
	if err != nil {
		t.Fatal("Method SendStoreQuery returned error:", err)
	}
	log.Lvl2("Method SendStoreQuery correctly returned no error")

	// Retrieve the data

	log.Lvl2("Going to retrieve data. Should not return error")
	retrData, err := c.SendRetrieveQuery(cid)
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

	size := 3
	roster := genLocalTestRoster(size)

	// Create session

	paramsIdx := 0
	clientID := "TestSumQuery"
	log.Lvl2("Going to create new session. Should not return error")
	c, _, _, err := testNewClientCreateSession(roster, paramsIdx, clientID) // We don't use the session
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

	// Store the first vector

	log.Lvl2("Going to store first vector. Should not return error")
	data1 := p.Coeffs[0] // Only one modulus exists
	cid1, err := c.SendStoreQuery(data1)
	if err != nil {
		t.Fatal("Method SendStoreQuery for first vector returned error:", err)
	}
	log.Lvl2("Method SendStoreQuery for first vector correctly returned no error")

	// Store the second vector

	log.Lvl2("Going to store second vector. Should not return error")
	data2 := q.Coeffs[0] // Only one modulus exists
	cid2, err := c.SendStoreQuery(data2)
	if err != nil {
		t.Fatal("Method SendStoreQuery for second vector returned error:", err)
	}
	log.Lvl2("Method SendStoreQuery for second vector correctly returned no error")

	// Sum the vectors remotely

	log.Lvl2("Going to sum the two vectors remotely. Should not return error")
	cidSum, err := c.SendSumQuery(cid1, cid2)
	if err != nil {
		t.Fatal("Method SendSumQuery returned error:", err)
	}
	log.Lvl2("Method SendSumQuery correctly returned no error")

	// Sum the vectors locally

	sum := ctx.NewPoly()
	ctx.Add(p, q, sum)
	origSum := sum.Coeffs[0] // Only one modulus is present

	// Retrieve the remote sum

	log.Lvl2("Going to retrieve the remote sum. Should not return error")
	retrSum, err := c.SendRetrieveQuery(cidSum)
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

// TODO: Why doesn't it work without relinearisation? Isn't the decryptor supposed to work anyway?
func TestMultiplyQuery(t *testing.T) {
	log.SetDebugVisible(3)
	log.Lvl1("Testing Multiply query")

	size := 3
	roster := genLocalTestRoster(size)

	// Create session

	paramsIdx := 1
	clientID := "TestMultiplyQuery"
	log.Lvl2("Going to create new session. Should not return error")
	c, _, _, err := testNewClientCreateSession(roster, paramsIdx, clientID) // We don't use the session
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

	// Store the first vector

	log.Lvl2("Going to store first vector. Should not return error")
	data1 := p.Coeffs[0] // Only one modulus exists
	cid1, err := c.SendStoreQuery(data1)
	if err != nil {
		t.Fatal("Method SendStoreQuery for first vector returned error:", err)
	}
	log.Lvl2("Method SendStoreQuery for first vector correctly returned no error")

	// Store the second vector

	log.Lvl2("Going to store second vector. Should not return error")
	data2 := q.Coeffs[0] // Only one modulus exists
	cid2, err := c.SendStoreQuery(data2)
	if err != nil {
		t.Fatal("Method SendStoreQuery for second vector returned error:", err)
	}
	log.Lvl2("Method SendStoreQuery for second vector correctly returned no error")

	// Multiply the vectors remotely

	log.Lvl2("Going to multiply the two vectors remotely. Should not return error")
	cidMul, err := c.SendMultiplyQuery(cid1, cid2)
	if err != nil {
		t.Fatal("Method SendMultiplyQuery returned error:", err)
	}
	log.Lvl2("Method SendMultiplyQuery correctly returned no error")

	// Multiply the vectors locally

	mul := ctx.NewPoly()
	ctx.MulCoeffs(p, q, mul)
	origMul := mul.Coeffs[0] // Only one modulus is present

	// Retrieve the remote product

	log.Lvl2("Going to retrieve the remote product. Should not return error")
	retrMul, err := c.SendRetrieveQuery(cidMul)
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

func TestMultiplyRelinQuery(t *testing.T) {
	log.SetDebugVisible(3)
	log.Lvl1("Testing Multiply and Relin query")

	size := 3
	roster := genLocalTestRoster(size)

	// Create session

	paramsIdx := 0
	clientID := "TestMultiplyRelinQuery"
	log.Lvl2("Going to create new session. Should not return error")
	c, _, _, err := testNewClientCreateSession(roster, paramsIdx, clientID) // We don't use the session
	if err != nil {
		t.Fatal("Method CreateSession returned error:", err)
	}
	log.Lvl2("Method CreateSession correctly returned no error")

	// Generate evaluation key

	log.Lvl2("Going to generate evaluation key. Should not return error")
	err = c.SendGenEvalKeyQuery()
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

	// Store the first vector

	log.Lvl2("Going to store first vector. Should not return error")
	data1 := p.Coeffs[0] // Only one modulus exists
	cid1, err := c.SendStoreQuery(data1)
	if err != nil {
		t.Fatal("Method SendStoreQuery for first vector returned error:", err)
	}
	log.Lvl2("Method SendStoreQuery for first vector correctly returned no error")

	// Store the second vector

	log.Lvl2("Going to store second vector. Should not return error")
	data2 := q.Coeffs[0] // Only one modulus exists
	cid2, err := c.SendStoreQuery(data2)
	if err != nil {
		t.Fatal("Method SendStoreQuery for second vector returned error:", err)
	}
	log.Lvl2("Method SendStoreQuery for second vector correctly returned no error")

	// Multiply the vectors remotely

	log.Lvl2("Going to multiply the two vectors remotely. Should not return error")
	cidMul, err := c.SendMultiplyQuery(cid1, cid2)
	if err != nil {
		t.Fatal("Method SendMultiplyQuery returned error:", err)
	}
	log.Lvl2("Method SendMultiplyQuery correctly returned no error")

	// Relinearise the remote product (remotely)

	log.Lvl2("Going to relinearise the remote product (remotely). Should not return error")
	_, err = c.SendRelinQuery(cidMul) // The CipherID doesn't change
	if err != nil {
		t.Fatal("Method SendRelinQuery returned error:", err)
	}
	log.Lvl2("Method SendRelinQuery correctly returned no error")

	// Multiply the vectors locally

	mul := ctx.NewPoly()
	ctx.MulCoeffs(p, q, mul)
	origMul := mul.Coeffs[0] // Only one modulus is present

	// Retrieve the remote product

	log.Lvl2("Going to retrieve the remote product. Should not return error")
	retrMul, err := c.SendRetrieveQuery(cidMul)
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
// Specifically, what's done is the following:
// a, b <-$ random
// ab <- Mul(a, b)
// ab <- Relin(ab)
// c, d <-$ random
// cd <- Mul(c, d)
// cd <- Relin(cd)
// abcd <- Mul(ab, cd)
// abcd <- Relin(abcd)
// TODO: interesting. With paramsIdx = 0 it never works. With paramsIdx >= 1 it works even without refresh
func TestRefreshQuery(t *testing.T) {
	log.SetDebugVisible(3)
	log.Lvl1("Testing Refresh query")

	size := 3
	roster := genLocalTestRoster(size)

	// Create session

	paramsIdx := 1
	clientID := "TestRefreshQuery"
	log.Lvl2("Going to create new session. Should not return error")
	client, _, _, err := testNewClientCreateSession(roster, paramsIdx, clientID) // We don't use the session
	if err != nil {
		t.Fatal("Method CreateSession returned error:", err)
	}
	log.Lvl2("Method CreateSession correctly returned no error")

	// Generate evaluation key

	log.Lvl2("Going to generate evaluation key. Should not return error")
	err = client.SendGenEvalKeyQuery()
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

	// Store a

	log.Lvl2("Going to store \"a\". Should not return error")
	cidA, err := client.SendStoreQuery(a.Coeffs[0]) // Only one modulus exists
	if err != nil {
		t.Fatal("Method SendStoreQuery for \"a\" returned error:", err)
	}
	log.Lvl2("Method SendStoreQuery for \"a\" correctly returned no error")

	// Store b

	log.Lvl2("Going to store \"b\". Should not return error")
	cidB, err := client.SendStoreQuery(b.Coeffs[0]) // Only one modulus exists
	if err != nil {
		t.Fatal("Method SendStoreQuery for \"b\" returned error:", err)
	}
	log.Lvl2("Method SendStoreQuery for \"b\" correctly returned no error")

	// Multiply a and b remotely

	log.Lvl2("Going to multiply \"a\" and \"b\" remotely. Should not return error")
	cidAB, err := client.SendMultiplyQuery(cidA, cidB)
	if err != nil {
		t.Fatal("Method SendMultiplyQuery for\"a\" and \"b\" returned error:", err)
	}
	log.Lvl2("Method SendMultiplyQuery for \"a\" and \"b\" correctly returned no error")

	// Relinearise the remote ab (remotely)

	log.Lvl2("Going to relinearise \"ab\" (remotely). Should not return error")
	_, err = client.SendRelinQuery(cidAB) // The CipherID doesn't change
	if err != nil {
		t.Fatal("Method SendRelinQuery for \"ab\" returned error:", err)
	}
	log.Lvl2("Method SendRelinQuery for \"ab\" correctly returned no error")

	// Multiply a and b locally

	ab := ctx.NewPoly()
	ctx.MulCoeffs(a, b, ab)

	// Retrieve the remote ab

	log.Lvl2("Going to retrieve the remote \"ab\". Should not return error")
	retr, err := client.SendRetrieveQuery(cidAB)
	if err != nil {
		t.Fatal("Method SendRetrieveQuery for \"ab\" returned error:", err)
	}
	log.Lvl2("Method SendRetrieveQuery for \"ab\" correctly returned no error")

	// Test for equality

	log.Lvl2("Going to test for equality. Should be the same")
	if !utils.Equalslice(ab.Coeffs[0], retr) {
		t.Fatal("Original \"ab\" and retrieved \"ab\" are not the same")
	}
	log.Lvl2("Original \"ab\" and retrieved \"ab\" are the same")

	// Generate c and d

	log.Lvl2("Going to generate c and d. Should not return error")
	ctx, c, d, err := testGenRandomPolys(paramsIdx)
	if err != nil {
		t.Fatal("Could not generate c and d:", err)
	}
	log.Lvl2("Successfully generated c and d")

	// Store c

	log.Lvl2("Going to store \"c\". Should not return error")
	cidC, err := client.SendStoreQuery(c.Coeffs[0]) // Only one modulus exists
	if err != nil {
		t.Fatal("Method SendStoreQuery for \"c\" returned error:", err)
	}
	log.Lvl2("Method SendStoreQuery for \"c\" correctly returned no error")

	// Store d

	log.Lvl2("Going to store \"d\". Should not return error")
	cidD, err := client.SendStoreQuery(d.Coeffs[0]) // Only one modulus exists
	if err != nil {
		t.Fatal("Method SendStoreQuery for \"d\" returned error:", err)
	}
	log.Lvl2("Method SendStoreQuery for \"d\" correctly returned no error")

	// Multiply c and d remotely

	log.Lvl2("Going to multiply \"c\" and \"d\" remotely. Should not return error")
	cidCD, err := client.SendMultiplyQuery(cidC, cidD)
	if err != nil {
		t.Fatal("Method SendMultiplyQuery for\"c\" and \"d\" returned error:", err)
	}
	log.Lvl2("Method SendMultiplyQuery for \"c\" and \"d\" correctly returned no error")

	// Relinearise the remote cd (remotely)

	log.Lvl2("Going to relinearise \"cd\" (remotely). Should not return error")
	_, err = client.SendRelinQuery(cidCD) // The CipherID doesn't change
	if err != nil {
		t.Fatal("Method SendRelinQuery for \"cd\" returned error:", err)
	}
	log.Lvl2("Method SendRelinQuery for \"cd\" correctly returned no error")

	// Multiply c and d locally

	cd := ctx.NewPoly()
	ctx.MulCoeffs(c, d, cd)

	// Retrieve the remote cd

	log.Lvl2("Going to retrieve the remote \"cd\". Should not return error")
	retr, err = client.SendRetrieveQuery(cidCD)
	if err != nil {
		t.Fatal("Method SendRetrieveQuery for \"cd\" returned error:", err)
	}
	log.Lvl2("Method SendRetrieveQuery for \"cd\" correctly returned no error")

	// Test for equality

	log.Lvl2("Going to test for equality. Should be the same")
	if !utils.Equalslice(cd.Coeffs[0], retr) {
		t.Fatal("Original \"cd\" and retrieved \"cd\" are not the same")
	}
	log.Lvl2("Original \"cd\" and retrieved \"cd\" are the same")

	// Multiply ab and cd remotely

	log.Lvl2("Going to multiply \"ab\" and \"cd\" remotely. Should not return error")
	cidABCD, err := client.SendMultiplyQuery(cidAB, cidCD)
	if err != nil {
		t.Fatal("Method SendMultiplyQuery for\"ab\" and \"cd\" returned error:", err)
	}
	log.Lvl2("Method SendMultiplyQuery for \"ab\" and \"cd\" correctly returned no error")

	// Relinearise the remote abcd (remotely)

	log.Lvl2("Going to relinearise \"abcd\" (remotely). Should not return error")
	_, err = client.SendRelinQuery(cidABCD) // The CipherID doesn't change
	if err != nil {
		t.Fatal("Method SendRelinQuery for \"abcd\" returned error:", err)
	}
	log.Lvl2("Method SendRelinQuery for \"abcd\" correctly returned no error")

	// Multiply ab and cd locally

	abcd := ctx.NewPoly()
	ctx.MulCoeffs(ab, cd, abcd)

	// Refresh the remote abcd

	log.Lvl2("Going to refresh \"abcd\" (remotely). Should not return error")
	_, err = client.SendRefreshQuery(cidABCD) // The CipherID doesn't change
	if err != nil {
		t.Fatal("Method SendRefreshQuery for \"abcd\" returned error:", err)
	}
	log.Lvl2("Method SendRefreshQuery for \"abcd\" correctly returned no error")

	// Retrieve the remote abcd

	log.Lvl2("Going to retrieve the remote \"abcd\". Should not return error")
	retr, err = client.SendRetrieveQuery(cidABCD)
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

// TODO: what does rotation do? How to test that it works?

/*

func TestRotation(t *testing.T) {
	log.SetDebugVisible(4)
	size := 5
	K := 2
	rotIdx := bfv.RotationLeft
	local := onet.NewLocalTest(utils.SUITE)
	_, el, _ := local.GenTree(size, true)

	client := NewClient(el.List[0], "0")
	seed := []byte{'l', 'a', 't', 't', 'i', 'g', 'o'}

	err := client.SendCreateSessionQuery(el, true, false, true, uint64(K), rotIdx, 0, seed)
	if err != nil {
		t.Fatal(err)
		return
	}
	<-time.After(2 * time.Second)

	client1 := NewClient(el.List[1], "1")

	q, err := client1.SendKeyQuery(true, false, false, 0)
	log.Lvl1("Response of query : ", q)
	<-time.After(time.Second)
	data := make([]byte, testCoeffSize)
	n, err := rand.Read(data)
	if err != nil || n != testCoeffSize {
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
	client2 := NewClient(el.List[2], "2")
	got, err := client2.SendRetrieveQuery(&resultRot)

	//We need to split it in two
	got1, got2 := got[:testCoeffSize/2], got[testCoeffSize/2:]
	data1, data2 := data[:testCoeffSize/2], data[testCoeffSize/2:]

	expected1 := make([]byte, testCoeffSize/2)
	expected2 := make([]byte, testCoeffSize/2)

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

*/
