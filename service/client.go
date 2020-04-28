// This file contains the behaviour of the client, defined by the struct Client and its methods, each of which
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
	"lattigo-smc/service/circuit"
	"lattigo-smc/service/messages"
	"lattigo-smc/service/session"
	"lattigo-smc/utils"
)

// Client represents a client. It is largely immutable: the only thing that can change after it has been
// constructed is the session it is bound to, and only with an explicit call to CloseSession or UnbindFromSession.
type Client struct {
	sessionClient *onet.Client
	circuitClient *onet.Client

	clientID string
	// The server in the system that will always be contacted for queries (most likely the server side of this node).
	entryPoint *network.ServerIdentity

	// The information on the session this Client is currently attached to
	sessionID messages.SessionID
	masterPK  *bfv.PublicKey
	encryptor bfv.Encryptor

	// Parameters for local encryption and decryption. Useful for Store and Retrieve queries.
	// They are set once and for all at construction time.
	params    *bfv.Parameters
	encoder   bfv.Encoder
	decryptor bfv.Decryptor
	sk        *bfv.SecretKey
	pk        *bfv.PublicKey
}

// String returns the string representation of the client.
func (c *Client) String() string {
	return "[Client " + c.clientID + "]"
}

//NewClient creates a new unbound client given the definitive parameters.
func NewClient(entryPoint *network.ServerIdentity, clientID string, params *bfv.Parameters) *Client {
	log.Lvl1("Client constructor called for clientID:", clientID)

	client := &Client{
		sessionClient: onet.NewClient(utils.SUITE, session.ServiceName),
		circuitClient: onet.NewClient(utils.SUITE, circuit.ServiceName),

		clientID:   clientID,
		entryPoint: entryPoint,

		sessionID: messages.NilSessionID,
		masterPK:  nil,
	}

	client.params = params.Copy()
	client.encoder = bfv.NewEncoder(client.params)
	keygen := bfv.NewKeyGenerator(client.params)
	client.sk, client.pk = keygen.GenKeyPair()
	client.decryptor = bfv.NewDecryptor(client.params, client.sk)

	return client
}

// isBound returns whether or not the client is already bound to a session.
func (c *Client) isBound() bool {
	return c.sessionID != messages.NilSessionID
}

// Sends a CreateSessionQuery to the system (only if the client isn't already bound), and then
// a GenPubKeyQuery, because a session without its masterPK makes no sense
// The argument "seed" can be nil, in which case a default one is used.
func (c *Client) CreateSession(roster *onet.Roster, seed []byte) (messages.SessionID, *bfv.PublicKey, error) {
	log.Lvl1(c, "Creating new session")

	// Check that the client isn't already bound
	if c.isBound() {
		err := errors.New("Cannot CreateSession: is already bound")
		log.Error(c, err)
		return messages.NilSessionID, nil, err
	}

	// Create session

	// Possibly substitute seed with default
	if seed == nil {
		seed = []byte("soreta")
	}

	// Craft CreateSessionQuery and prepare response
	sessQuery := &messages.CreateSessionQuery{roster, c.params}
	sessResp := &messages.CreateSessionResponse{}

	// Send query
	log.Lvl2(c, "Sending CreateSession query to entry point")
	err := c.sessionClient.SendProtobuf(c.entryPoint, sessQuery, sessResp)
	if err != nil {
		log.Error(c, "CreateSession query returned error:", err)
		return messages.NilSessionID, nil, err
	}
	if !sessResp.Valid {
		err = errors.New("Received response is invalid. Service could not create session.")
		log.Error(c, err)
		return messages.NilSessionID, nil, err
	}
	log.Lvl3(c, "CreateSession query was successful!")

	// Generate master public key

	// Craft GenPubKeyQuery and prepare response
	pubKeyQuery := &messages.GenPubKeyQuery{sessResp.SessionID, seed}
	pubKeyResp := &messages.GenPubKeyResponse{}

	// Send query
	log.Lvl2(c, "Sending GenPubKey query to entry point")
	err = c.sessionClient.SendProtobuf(c.entryPoint, pubKeyQuery, pubKeyResp)
	if err != nil {
		log.Error(c, "GenPubKey query returned error:", err)
		return messages.NilSessionID, nil, err
	}
	if !pubKeyResp.Valid {
		err = errors.New("Received response is invalid. Service could not generate public key.")
		log.Error(c, err)
		return messages.NilSessionID, nil, err
	}
	log.Lvl3(c, "GenPubKey query was successful!")

	// Bind to this new session
	log.Lvl3(c, "Successfully created session and generated public key: binding to session")
	// We can ignore the error, since we already checked that the client is not bound.
	_ = c.BindToSession(sessResp.SessionID, pubKeyResp.MasterPublicKey)

	return sessResp.SessionID, pubKeyResp.MasterPublicKey, nil
}

// BindToSession binds the client to an already existing session, without triggering any query to the system.
func (c *Client) BindToSession(sessionID messages.SessionID, masterPK *bfv.PublicKey) error {
	// Check that the client is not bound
	if c.isBound() {
		err := errors.New("Cannot BindToSession: is already bound")
		log.Error(c, err)
		return err
	}

	// Set session parameters
	c.sessionID = sessionID
	c.masterPK = masterPK // TODO: deep copy
	c.encryptor = bfv.NewEncryptorFromPk(c.params, c.masterPK)

	return nil
}

// Sends a CloseSessionQuery to the system (only if the client is actually bound).
// Only one of the (possibly many) client bound to a Session can close it.
func (c *Client) CloseSession() error {
	log.Lvl1(c, "Closing session")

	// Check that the client is actually bound
	if !c.isBound() {
		err := errors.New("Cannot CloseSession: is not bound")
		log.Error(c, err)
		return err
	}

	// Close session

	// Craft CloseSessionQuery and prepare response
	query := &messages.CloseSessionQuery{c.sessionID}
	resp := &messages.CloseSessionResponse{}

	// Send query
	log.Lvl2(c, "Sending CloseSession query to entry point")
	err := c.sessionClient.SendProtobuf(c.entryPoint, query, resp)
	if err != nil {
		log.Error(c, "CloseSession query returned error:", err)
		return err
	}
	if !resp.Valid {
		err = errors.New("Received response is invalid. Service could not close session.")
		log.Error(c, err)
		return err
	}

	// Unbind from current session
	log.Lvl3(c, "Successfully closed current session: unbinding")
	// We can ignore the error, since we already checked that the client is actually bound.
	_ = c.UnbindFromSession()

	return nil
}

// UnbindFromSession unbinds the client from its current session, without triggering any query to the system.
func (c *Client) UnbindFromSession() error {
	// Check that the client is bound
	if !c.isBound() {
		err := errors.New("Cannot UnbindFromSession: is not bound")
		log.Error(c, err)
		return err
	}

	// Unset session parameters
	c.sessionID = messages.NilSessionID
	c.masterPK = nil
	c.encryptor = nil

	return nil
}

// SendGenEvalKeyQuery send a query to generate the evaluation key.
// The argument "seed" can be nil, in which case a default one is used.
func (c *Client) SendGenEvalKeyQuery(seed []byte) error {
	log.Lvl1(c, "Called to send a query to generate the evaluation key")

	// Check that the client is bound
	if !c.isBound() {
		err := errors.New("Cannot send query: is not bound")
		log.Error(c, err)
		return err
	}

	// Possibly substitute seed with default
	if seed == nil {
		seed = []byte("soreta")
	}

	// Craft query and prepare response
	query := &messages.GenEvalKeyQuery{c.sessionID, seed}
	resp := &messages.GenEvalKeyResponse{}

	// Send query
	log.Lvl2(c, "Sending query to entry point")
	err := c.sessionClient.SendProtobuf(c.entryPoint, query, resp)
	if err != nil {
		log.Error(c, "GenEvalKey query returned error:", err)
		return err
	}
	if !resp.Valid {
		err = errors.New("Received response is invalid: service could not generate evaluation key")
		log.Error(c, err)
		return err
	}

	log.Lvl2(c, "GenEvalKey query was successful")

	return nil
}

// SendGenRotKeyQuery send a query to generate the rotation key.
// The argument "seed" can be nil, in which case a default one is used.
func (c *Client) SendGenRotKeyQuery(rotIdx int, K uint64, seed []byte) error {
	log.Lvl1(c, "Called to send a query to generate the rotation key")

	// Check that the client is bound
	if !c.isBound() {
		err := errors.New("Cannot send query: is not bound")
		log.Error(c, err)
		return err
	}

	// Possibly substitute seed with default
	if seed == nil {
		seed = []byte("soreta")
	}

	// Craft query and prepare response
	query := &messages.GenRotKeyQuery{c.sessionID, rotIdx, K, seed}
	resp := &messages.GenRotKeyResponse{}

	// Send query
	log.Lvl2(c, "Sending query to entry point")
	err := c.sessionClient.SendProtobuf(c.entryPoint, query, resp)
	if err != nil {
		log.Error(c, "GenRotKey query returned error:", err)
		return err
	}
	if !resp.Valid {
		err = errors.New("Received response is invalid: service could not generate rotation key")
		log.Error(c, err)
		return err
	}

	log.Lvl2(c, "GenRotKey query was successful")

	return nil
}

// SendKeyQuery sends a query to have the entry point retrieve the specified keys.
func (c *Client) SendKeyQuery(getEvK, getRtK bool) (bool, bool, error) {
	log.Lvl1(c, "Called to send a key query")

	// Build query
	query := messages.KeyQuery{c.sessionID, getEvK, getRtK}

	resp := messages.KeyResponse{}

	// Send query
	log.Lvl2(c, "Sending query to entry point")
	err := c.sessionClient.SendProtobuf(c.entryPoint, &query, &resp)
	if err != nil {
		log.Error(c, "Key query returned error:", err)
		return false, false, err
	}
	if !resp.Valid {
		err = errors.New("Server sent invalid response")
		log.Error(c, err)
		return false, false, err
	}

	log.Lvl2(c, "Key query was successful")

	return resp.EvalKeyObtained, resp.RotKeyObtained, nil
}

// SendStoreQuery sends a query to store in the system the provided vector. The vector is encrypted locally.
func (c *Client) SendStoreQuery(data []uint64) (messages.CipherID, error) {
	log.Lvl1(c, "Called to send a store query")

	// Check that the client is bound
	if !c.isBound() {
		err := errors.New("Cannot send query: is not bound")
		log.Error(c, err)
		return messages.NilCipherID, err
	}

	// Encrypt data
	plain := bfv.NewPlaintext(c.params)
	c.encoder.EncodeUint(data, plain)
	cipher := c.encryptor.EncryptNew(plain)

	// Craft query and prepare response
	query := &messages.StoreQuery{c.sessionID, cipher}
	resp := &messages.StoreResponse{}

	// Send query
	log.Lvl2(c, "Sending query to entry point")
	err := c.sessionClient.SendProtobuf(c.entryPoint, query, resp)
	if err != nil {
		log.Error(c, "Store query returned error:", err)
		return messages.NilCipherID, err
	}
	if !resp.Valid {
		err = errors.New("Received response is invalid: service could not store")
		log.Error(c, err)
		return messages.NilCipherID, err
	}

	log.Lvl2(c, "Store query was successful")

	return resp.CipherID, nil
}

// SendRetrieveQuery sends a query to retrieve the ciphertext indexed by cipherID, switched under the
// client's own public key. The switched ciphertext is decrypted locally and returned in clear.
func (c *Client) SendRetrieveQuery(cipherID messages.CipherID) ([]uint64, error) {
	log.Lvl1(c, "Called to send a retrieve query")

	// Check that the client is bound
	if !c.isBound() {
		err := errors.New("Cannot send query: is not bound")
		log.Error(c, err)
		return nil, err
	}

	// Craft query and prepare response
	query := &messages.RetrieveQuery{c.sessionID, c.pk, cipherID}
	resp := &messages.RetrieveResponse{}

	// Send query
	log.Lvl2(c, "Sending query to entry point")
	err := c.circuitClient.SendProtobuf(c.entryPoint, query, resp)
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
func (c *Client) SendSumQuery(cipherID1, cipherID2 messages.CipherID) (messages.CipherID, error) {
	log.Lvl1(c, "Called to send a sum query")

	// Check that the client is bound
	if !c.isBound() {
		err := errors.New("Cannot send query: is not bound")
		log.Error(c, err)
		return messages.NilCipherID, err
	}

	// Craft query and prepare response
	query := &messages.SumQuery{c.sessionID, cipherID1, cipherID2}
	resp := &messages.SumResponse{}

	// Send query
	log.Lvl2(c, "Sending query to entry point")
	err := c.circuitClient.SendProtobuf(c.entryPoint, query, resp)
	if err != nil {
		log.Error(c, "Sum query returned error:", err)
		return messages.NilCipherID, err
	}
	if !resp.Valid {
		err = errors.New("Received response is invalid. Service could not sum.")
		log.Error(c, err)
		return messages.NilCipherID, err
	}

	log.Lvl2(c, "Sum query was successful")

	return resp.NewCipherID, nil
}

// SendMultiplyQuery sends a query to sum two ciphertexts.
func (c *Client) SendMultiplyQuery(cipherID1, cipherID2 messages.CipherID) (messages.CipherID, error) {
	log.Lvl1(c, "Called to send a multiply query")

	// Check that the client is bound
	if !c.isBound() {
		err := errors.New("Cannot send query: is not bound")
		log.Error(c, err)
		return messages.NilCipherID, err
	}

	// Craft query and prepare response
	query := &messages.MultiplyQuery{c.sessionID, cipherID1, cipherID2}
	resp := &messages.MultiplyResponse{}

	// Send query
	log.Lvl2(c, "Sending query to entry point")
	err := c.circuitClient.SendProtobuf(c.entryPoint, query, resp)
	if err != nil {
		log.Error(c, "Multiply query returned error:", err)
		return messages.NilCipherID, err
	}
	if !resp.Valid {
		err = errors.New("Received response is invalid. Service could not multiply.")
		log.Error(c, err)
		return messages.NilCipherID, err
	}

	log.Lvl2(c, "Multiply query was successful")

	return resp.NewCipherID, nil
}

// SendRelinQuery sends a query to relinearise the ciphertext indexed by cipherID.
func (c *Client) SendRelinQuery(cipherID messages.CipherID) (messages.CipherID, error) {
	log.Lvl1(c, "Called to send a relinearisation query")

	// Check that the client is bound
	if !c.isBound() {
		err := errors.New("Cannot send query: is not bound")
		log.Error(c, err)
		return messages.NilCipherID, err
	}

	// Craft query and prepare response
	query := &messages.RelinQuery{c.sessionID, cipherID}
	resp := &messages.RelinResponse{}

	// Send query
	log.Lvl2(c, "Sending query to entry point")
	err := c.circuitClient.SendProtobuf(c.entryPoint, query, resp)
	if err != nil {
		log.Error(c, "Relinearisation query returned error:", err)
		return messages.NilCipherID, err
	}
	if !resp.Valid {
		err = errors.New("Received response is invalid. Service could not relinearise.")
		log.Error(c, err)
		return messages.NilCipherID, err
	}

	log.Lvl2(c, "Relinearisation query was successful")

	return resp.NewCipherID, nil
}

// SendRotationQuery sends a query to perform arotIdx-rotation of k positions on the ciphertext indexed by cipherID.
func (c *Client) SendRotationQuery(cipherID messages.CipherID, rotIdx int, K uint64) (messages.CipherID, error) {
	log.Lvl1(c, "Called to send a rotation query")

	// Check that the client is bound
	if !c.isBound() {
		err := errors.New("Cannot send query: is not bound")
		log.Error(c, err)
		return messages.NilCipherID, err
	}

	// Craft query and prepare response
	query := &messages.RotationQuery{c.sessionID, cipherID, K, rotIdx}
	resp := &messages.RotationResponse{}

	// Send query
	log.Lvl2(c, "Sending query to entry point")
	err := c.circuitClient.SendProtobuf(c.entryPoint, query, resp)
	if err != nil {
		log.Error(c, "Refresh query returned error:", err)
		return messages.NilCipherID, err
	}
	if !resp.Valid {
		err = errors.New("Received response is invalid. Service could not rotate.")
		log.Error(c, err)
		return messages.NilCipherID, err
	}

	log.Lvl2(c, "Refresh query was successful")

	return resp.NewCipherID, nil
}

// SendRefreshQuery sends a query to refresh the ciphertext indexed by cipherID.
// The argument "seed" can be nil, in which case a default one is used.
func (c *Client) SendRefreshQuery(cipherID messages.CipherID, seed []byte) (messages.CipherID, error) {
	log.Lvl1(c, "Called to send a refresh query")

	// Check that the client is bound
	if !c.isBound() {
		err := errors.New("Cannot send query: is not bound")
		log.Error(c, err)
		return messages.NilCipherID, err
	}

	// Craft query and prepare response
	query := &messages.RefreshQuery{c.sessionID, cipherID, seed}
	resp := &messages.RefreshResponse{}

	// Send query
	log.Lvl2(c, "Sending query to entry point")
	err := c.circuitClient.SendProtobuf(c.entryPoint, query, resp)
	if err != nil {
		log.Error(c, "Refresh query returned error:", err)
		return messages.NilCipherID, err
	}
	if !resp.Valid {
		err = errors.New("Received response is invalid. Service could not refresh.")
		log.Error(c, err)
		return messages.NilCipherID, err
	}

	log.Lvl2(c, "Refresh query was successful")

	return resp.NewCipherID, nil
}

// SendEncToSharesQuery sends a query to share the ciphertext indexed by cipherID.
func (c *Client) SendEncToSharesQuery(cipherID messages.CipherID) (messages.SharesID, error) {
	log.Lvl1(c, "Called to send an enc-to-shares query")

	// Check that the client is bound
	if !c.isBound() {
		err := errors.New("Cannot send query: is not bound")
		log.Error(c, err)
		return messages.NilSharesID, err
	}

	// Craft query and prepare response
	query := &messages.EncToSharesQuery{c.sessionID, cipherID}
	resp := &messages.EncToSharesResponse{}

	// Send query
	log.Lvl2(c, "Sending query to entry point")
	err := c.circuitClient.SendProtobuf(c.entryPoint, query, resp)
	if err != nil {
		log.Error(c, "Enc-to-shares query returned error:", err)
		return messages.NilSharesID, err
	}
	if !resp.Valid {
		err = errors.New("Received response is invalid. Service could not share.")
		log.Error(c, err)
		return messages.NilSharesID, err
	}

	log.Lvl2(c, "Enc-to-shares query was successful")

	return resp.SharesID, nil
}

// SendSharesToEncQuery sends a query to re-encrypt the ciphertext with the shares indexed by cipherID.
// The argument "seed" can be nil, in which case a default one is used.
func (c *Client) SendSharesToEncQuery(sharesID messages.SharesID, seed []byte) (messages.CipherID, error) {
	log.Lvl1(c, "Called to send a shares-to-enc query")

	// Check that the client is bound
	if !c.isBound() {
		err := errors.New("Cannot send query: is not bound")
		log.Error(c, err)
		return messages.NilCipherID, err
	}

	// Craft query and prepare response
	query := &messages.SharesToEncQuery{c.sessionID, sharesID, seed}
	resp := &messages.SharesToEncResponse{}

	// Send query
	log.Lvl2(c, "Sending query to entry point")
	err := c.circuitClient.SendProtobuf(c.entryPoint, query, resp)
	if err != nil {
		log.Error(c, "Shares-to-enc query returned error:", err)
		return messages.NilCipherID, err
	}
	if !resp.Valid {
		err = errors.New("Received response is invalid. Service could not share.")
		log.Error(c, err)
		return messages.NilCipherID, err
	}

	log.Lvl2(c, "Shares-to-enc query was successful")

	return resp.NewCipherID, nil
}
