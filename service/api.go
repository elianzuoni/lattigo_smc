// This file contains the behaviour of the client, defined by the struct API and its methods, each of which
// sends a specific query to the Service (more precisely, always to the same server in the system, specified
// at construct-time). The methods optionally return an error, if something goes wrong server-side, but they are
// guaranteed to return within a certain timeout. // TODO: implement timeout in HandleQuery server-side

package service

import (
	"errors"
	"github.com/ldsec/lattigo/bfv"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
	"lattigo-smc/utils"
)

// API represents a client
type API struct {
	*onet.Client

	clientID string

	// The server in the system that will always be contacted for queries.
	entryPoint *network.ServerIdentity

	// Parameters for local encryption and decryption. Useful for Store and Retrieve queries.
	paramsIdx uint64
	params    *bfv.Parameters
	encoder   bfv.Encoder
	encryptor bfv.Encryptor
	decryptor bfv.Decryptor
	sk        *bfv.SecretKey
	pk        *bfv.PublicKey
}

//NewLattigoSMCClient creates a new client for lattigo-smc
func NewLattigoSMCClient(entryPoint *network.ServerIdentity, clientID string, paramsIdx uint64) *API {
	client := &API{
		Client: onet.NewClient(utils.SUITE, ServiceName),

		clientID:   clientID,
		entryPoint: entryPoint,
	}

	client.paramsIdx = paramsIdx
	client.params = bfv.DefaultParams[paramsIdx]
	client.encoder = bfv.NewEncoder(client.params)
	keygen := bfv.NewKeyGenerator(client.params)
	client.sk, client.pk = keygen.GenKeyPair()
	client.encryptor = bfv.NewEncryptorFromSk(client.params, client.sk)
	client.decryptor = bfv.NewDecryptor(client.params, client.sk)

	return client
}

// SendSetupQuery sends a query for the roster to set up to generate the keys needed.
// TODO: why send roster and seed in query?
func (c *API) SendSetupQuery(entities *onet.Roster, genPublicKey, genEvaluationKey, genRotationKey bool,
	K uint64, rotIdx int, seed []byte) error {
	log.Lvl1(c, "Called to send a setup query")

	// Build query
	query := SetupQuery{
		Roster:                *entities,
		ParamsIdx:             c.paramsIdx,
		Seed:                  seed,
		GeneratePublicKey:     genPublicKey,
		GenerateEvaluationKey: genEvaluationKey,
		GenerateRotationKey:   genRotationKey,
		K:                     K,
		RotIdx:                rotIdx,
	}

	resp := SetupResponse{}

	// Send query
	log.Lvl2(c, "Sending query to entry point")
	err := c.SendProtobuf(c.entryPoint, &query, &resp)
	if err != nil {
		log.Error(c, "Setup query returned error:", err)
		return err
	}

	log.Lvl2(c, "Setup query was successful")

	// TODO: what policy to return error?
	return nil

}

// SendKeyQuery sends a query to have the entry point retrieve the specified keys.
func (c *API) SendKeyQuery(getPK, getEvK, getRtK bool, RotIdx int) error {
	log.Lvl1(c, "Called to send a key query")

	// Build query
	query := KeyQuery{
		PublicKey:     getPK,
		EvaluationKey: getEvK,
		RotationKey:   getRtK,
		RotIdx:        RotIdx,
	}

	resp := SetupResponse{}

	// Send query
	log.Lvl2(c, "Sending query to entry point")
	err := c.SendProtobuf(c.entryPoint, &query, &resp)
	if err != nil {
		log.Error(c, "Key query returned error:", err)
		return err
	}

	log.Lvl2(c, "Key query was successful")

	// TODO: what policy to return error?
	return nil
}

// SendStoreQuery sends a query to store in the system the provided vector. The vector is encrypted locally.
func (c *API) SendStoreQuery(data []uint64) (CipherID, error) {
	log.Lvl1(c, "Called to send a store query")

	// Build query
	plain := bfv.NewPlaintext(c.params)
	c.encoder.EncodeUint(data, plain)
	cipher := c.encryptor.EncryptNew(plain)
	query := StoreQuery{cipher}

	resp := StoreResponse{}

	// Send query
	log.Lvl2(c, "Sending query to entry point")
	err := c.SendProtobuf(c.entryPoint, &query, &resp)
	if err != nil {
		log.Error(c, "Store query returned error:", err)
		return NilCipherID, err
	}

	log.Lvl2(c, "Store query was successful")

	return resp.CipherID, nil
}

// SendRetrieveQuery sends a query to retrieve the clear-text vector corresponding to
// the ciphertext indexed by cipherID.
func (c *API) SendRetrieveQuery(cipherID CipherID) ([]uint64, error) {
	log.Lvl1(c, "Called to send a retrieve query")

	// Build query
	query := RetrieveQuery{
		PublicKey: c.pk,
		CipherID:  cipherID,
	}

	resp := RetrieveResponse{}

	// Send query
	log.Lvl2(c, "Sending query to entry point")
	err := c.SendProtobuf(c.entryPoint, &query, &resp)
	if err != nil {
		log.Error(c, "Retrieve query returned error:", err)
		return nil, err
	}
	if !resp.Valid {
		err = errors.New("Received response is invalid. Service could not retrieve.")
		log.Error(c, err)
		return nil, err
	}

	log.Lvl2(c, "Retrieve query was successful")

	// Recover clear-text vector
	log.Lvl4(c, "Recovering clear-text vector")
	plain := c.decryptor.DecryptNew(resp.Ciphertext)
	data := c.encoder.DecodeUint(plain)

	return data, nil
}

// SendSumQuery sends a query to sum two ciphertexts.
func (c *API) SendSumQuery(cipherID1, cipherID2 CipherID) (CipherID, error) {
	log.Lvl1(c, "Called to send a sum query")

	// Build query
	query := SumQuery{
		CipherID1: cipherID1,
		CipherID2: cipherID2,
	}

	resp := SumResponse{}

	// Send query
	log.Lvl2(c, "Sending query to entry point")
	err := c.SendProtobuf(c.entryPoint, &query, &resp)
	if err != nil {
		log.Error(c, "Sum query returned error:", err)
		return NilCipherID, err
	}
	if !resp.Valid {
		err = errors.New("Received response is invalid. Service could not sum.")
		log.Error(c, err)
		return NilCipherID, err
	}

	log.Lvl2(c, "Sum query was successful")

	return resp.NewCipherID, nil
}

// SendRelinQuery sends a query to relinearise the ciphertext indexed by cipherID.
func (c *API) SendRelinQuery(cipherID CipherID) (CipherID, error) {
	log.Lvl1(c, "Called to send a relinearisation query")

	// Build query
	query := RelinQuery{cipherID}

	resp := RelinResponse{}

	// Send query
	log.Lvl2(c, "Sending query to entry point")
	err := c.SendProtobuf(c.entryPoint, &query, &resp)
	if err != nil {
		log.Error(c, "Relinearisation query returned error:", err)
		return NilCipherID, err
	}
	if !resp.Valid {
		err = errors.New("Received response is invalid. Service could not relinearise.")
		log.Error(c, err)
		return NilCipherID, err
	}

	log.Lvl2(c, "Relinearisation query was successful")

	// We know the Service will store the relinearised ciphertext under the same CipherID as before.
	return cipherID, nil
}

// SendRefreshQuery sends a query to refresh the ciphertext indexed by cipherID.
func (c *API) SendRefreshQuery(cipherID CipherID) (CipherID, error) {
	log.Lvl1(c, "Called to send a refresh query")

	// Build query
	query := RefreshQuery{cipherID}

	resp := RefreshResponse{}

	// Send query
	log.Lvl2(c, "Sending query to entry point")
	err := c.SendProtobuf(c.entryPoint, &query, &resp)
	if err != nil {
		log.Error(c, "Refresh query returned error:", err)
		return NilCipherID, err
	}
	if !resp.Valid {
		err = errors.New("Received response is invalid. Service could not refresh.")
		log.Error(c, err)
		return NilCipherID, err
	}

	log.Lvl2(c, "Refresh query was successful")

	// We know the Service will store the refreshed ciphertext under the same CipherID as before.
	return cipherID, nil
}

// SendRotationQuery sends a query to perform a rotation of type rotType-k on the ciphertext indexed by cipherID.
func (c *API) SendRotationQuery(cipherID CipherID, K uint64, rotType int) (CipherID, error) {
	log.Lvl1(c, "Called to send a rotation query")

	// Build query
	query := RotationQuery{
		CipherID: cipherID,
		K:        K,
		RotIdx:   rotType,
	}

	resp := RotationResponse{}

	// Send query
	log.Lvl2(c, "Sending query to entry point")
	err := c.SendProtobuf(c.entryPoint, &query, &resp)
	if err != nil {
		log.Error(c, "Refresh query returned error:", err)
		return NilCipherID, err
	}
	if !resp.Valid {
		err = errors.New("Received response is invalid. Service could not rotate.")
		log.Error(c, err)
		return NilCipherID, err
	}

	log.Lvl2(c, "Refresh query was successful")

	return resp.New, nil
}

// String returns the string representation of the client.
func (c *API) String() string {
	return "[Client " + c.clientID + "]"
}
