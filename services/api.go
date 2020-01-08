package services

import (
	"github.com/ldsec/lattigo/bfv"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/util/key"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
	uuid "gopkg.in/satori/go.uuid.v1"
	"lattigo-smc/utils"
)

type API struct {
	*onet.Client
	clientID   string
	entryPoint *network.ServerIdentity

	//keys between client and server
	public  kyber.Point
	private kyber.Scalar
}

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

func (c *API) SendSumQuery() {

}

func (c *API) String() string {
	return "[Client " + c.clientID + "]"
}

func (c *API) SendWriteQuery(roster *onet.Roster, data []byte) (*uuid.UUID, error) {

	result := ServiceState{}
	query := QueryData{}
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

func (c *API) SendMultiplyQuery() {

}

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

type QueryPlaintext struct {
	uuid.UUID
	Innermessage bool
	PublicKey    bfv.PublicKey
	Ciphertext   bfv.Ciphertext
	Origin       *network.ServerIdentity
}

type ReplyPlaintext struct {
	uuid.UUID
	Ciphertext bfv.Ciphertext
}

func (c *API) GetPlaintext(roster *onet.Roster, id *uuid.UUID) ([]byte, error) {
	query := QueryPlaintext{UUID: *id, Innermessage: true}
	response := QueryData{}
	err := c.SendProtobuf(c.entryPoint, &query, &response)
	if err != nil {
		log.Lvl1("Error while sending : ", err)
		return []byte{}, err
	}

	data := response.Data
	return data, nil
}
