package services

import (
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/util/key"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
	uuid "gopkg.in/satori/go.uuid.v1"
	"lattigo-smc/utils"
)

//API represents a client
type API struct {
	*onet.Client
	clientID   string
	entryPoint *network.ServerIdentity

	//keys between client and server
	public  kyber.Point
	private kyber.Scalar
}

//NewLattigoSMCClient creates a new client for lattigo-smc
func NewLattigoSMCClient(entryPoint *network.ServerIdentity, clientID string) *API {
	keys := key.NewKeyPair(utils.SUITE)
	client := &API{
		Client:     onet.NewClient(utils.SUITE, ServiceName),
		clientID:   clientID,
		entryPoint: entryPoint,
		public:     keys.Public,
		private:    keys.Private,
	}

	return client
}

//SendSumQuery sends a query to sum up to ciphertext.
func (c *API) SendSumQuery() {

}

//SendMultiplyQuery sends a query to multiply 2 ciphertext.
func (c *API) SendMultiplyQuery() {

}

//SendWriteQuery send a query to write the data in the array. returns the UUID of the corresponding ciphertext.
func (c *API) SendWriteQuery(roster *onet.Roster, data []byte) (*uuid.UUID, error) {

	result := ServiceState{}
	query := QueryData{}
	//query.UUID = uuid.UUID{}
	query.Data = data
	query.Roster = *roster
	err := c.SendProtobuf(c.entryPoint, &query, &result)
	if err != nil {
		return nil, err
	}

	log.Lvl1(c, "sent a query to the server.")
	id := result.Id
	pending := result.Pending
	if pending {
		log.Warn("Pending transaction")
	}
	return &id, nil
}

//SendKeyRequest sends a request for the server to retrieve the keys needed.
func (c *API) SendKeyRequest(publickey, evaluationkey, rotationkey bool) (int, error) {
	kr := KeyRequest{
		PublicKey:     publickey,
		EvaluationKey: evaluationkey,
		RotationKey:   rotationkey,
	}

	resp := SetupReply{}
	err := c.SendProtobuf(c.entryPoint, &kr, &resp)

	return resp.Done, err
}

//SendSetupQuery sends a query for the roster to set up to generate the keys needed.
func (c *API) SendSetupQuery(entities *onet.Roster, generateEvaluationKey bool, paramsIdx uint64, seed []byte) error {
	log.Lvl1(c, "Sending a setup query to the roster")

	setupQuery := SetupRequest{*entities, paramsIdx, seed, generateEvaluationKey}
	resp := SetupReply{}
	err := c.SendProtobuf(c.entryPoint, &setupQuery, &resp)
	if err != nil {
		return err
	}

	log.Lvl1(c, " sent a setup request")
	return nil

}

//GetPlaintext send a request to retrieve the plaintext of the ciphertetx encrypted under id
func (c *API) GetPlaintext(roster *onet.Roster, id *uuid.UUID) ([]byte, error) {
	query := QueryPlaintext{UUID: *id}
	response := PlaintextReply{}
	err := c.SendProtobuf(c.entryPoint, &query, &response)
	if err != nil {
		log.Lvl1("Error while sending : ", err)
		return []byte{}, err
	}

	data := response.Data
	return data, nil
}

//String returns the string representation of the client
func (c *API) String() string {
	return "[Client " + c.clientID + "]"
}
