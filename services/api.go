//api contains the handler for the client to interact with the service. The client can perform various request to its server represented by its entryPoint
package services

import (
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
}

//NewLattigoSMCClient creates a new client for lattigo-smc
func NewLattigoSMCClient(entryPoint *network.ServerIdentity, clientID string) *API {
	client := &API{
		Client:     onet.NewClient(utils.SUITE, ServiceName),
		clientID:   clientID,
		entryPoint: entryPoint,
	}

	return client
}

//SendSetupQuery sends a query for the roster to set up to generate the keys needed.
func (c *API) SendSetupQuery(entities *onet.Roster, generatePublicKey, generateEvaluationKey, genRotationKey bool, K uint64, rotIdx int, paramsIdx uint64, seed []byte) error {
	log.Lvl1(c, "Sending a setup query to the roster")

	setupQuery := SetupRequest{*entities, paramsIdx, seed, generatePublicKey, generateEvaluationKey, genRotationKey, K, rotIdx}
	resp := SetupReply{}
	err := c.SendProtobuf(c.entryPoint, &setupQuery, &resp)
	if err != nil {
		return err
	}

	log.Lvl1(c, " sent a setup request")
	return nil

}

//SendKeyRequest sends a request for the server to retrieve the keys needed.
func (c *API) SendKeyRequest(publickey, evaluationkey, rotationkey bool, RotIdx int) (int, error) {
	kr := KeyRequest{
		PublicKey:     publickey,
		EvaluationKey: evaluationkey,
		RotationKey:   rotationkey,
		RotIdx:        RotIdx,
	}

	resp := SetupReply{}
	err := c.SendProtobuf(c.entryPoint, &kr, &resp)

	return resp.Done, err
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

//GetPlaintext send a request to retrieve the plaintext of the ciphertetx encrypted under id
func (c *API) GetPlaintext(id *uuid.UUID) ([]byte, error) {
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

//SendSumQuery sends a query to sum up to ciphertext.
func (c *API) SendSumQuery(id1, id2 uuid.UUID) (uuid.UUID, error) {
	query := SumQuery{
		UUID:  id1,
		Other: id2,
	}
	result := ServiceState{}
	err := c.SendProtobuf(c.entryPoint, &query, &result)
	if err != nil {
		return uuid.UUID{}, err
	}
	log.Lvl1("Got reply of sum query :", result.Id)
	return result.Id, nil

}

//SendMultiplyQuery sends a query to multiply 2 ciphertext.
func (c *API) SendMultiplyQuery(id1, id2 uuid.UUID) (uuid.UUID, error) {
	query := MultiplyQuery{
		UUID:  id1,
		Other: id2,
	}
	result := ServiceState{}
	err := c.SendProtobuf(c.entryPoint, &query, &result)
	if err != nil {
		return uuid.UUID{}, err
	}
	log.Lvl1("Got reply of multiply query :", result.Id)
	return result.Id, nil

}

//SendRelinQuery request for ciphertext id to be relinearized
func (c *API) SendRelinQuery(id uuid.UUID) (uuid.UUID, error) {
	query := RelinQuery{
		UUID: id,
	}
	result := ServiceState{}
	err := c.SendProtobuf(c.entryPoint, &query, &result)
	if err != nil {
		return uuid.UUID{}, err
	}
	log.Lvl1("Got reply of relinearization query :", result.Id)
	return result.Id, nil
}

//SendRefreshQuery send a query for ciphertext id to be refreshed.
func (c *API) SendRefreshQuery(id *uuid.UUID) (uuid.UUID, error) {
	query := RefreshQuery{*id, nil}

	result := ServiceState{}
	err := c.SendProtobuf(c.entryPoint, &query, &result)
	if err != nil {
		return uuid.UUID{}, err
	}
	log.Lvl1("Got reply of refresh query :", result.Id)
	return result.Id, nil

}

//SendRotationQuery send a query to perform a rotation of type rotType-K on id
func (c *API) SendRotationQuery(id uuid.UUID, K uint64, rotType int) (uuid.UUID, error) {
	query := RotationQuery{
		UUID:   id,
		RotIdx: rotType,
		K:      K,
	}

	result := ServiceState{}
	err := c.SendProtobuf(c.entryPoint, &query, &result)
	if err != nil {
		return uuid.UUID{}, err
	}

	log.Lvl1("Got reply of rotaiton : ", result.Id)
	return result.Id, err
}

//String returns the string representation of the client
func (c *API) String() string {
	return "[Client " + c.clientID + "]"
}
