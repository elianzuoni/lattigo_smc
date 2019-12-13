package services

import (
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/util/key"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
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

func (c *API) SendWriteQuery(roster *onet.Roster, qID QueryID, data []byte) (*QueryID, error) {
	var queryID QueryID

	result := ServiceState{}
	query := QueryData{}
	query.Data = data
	query.Roster = *roster
	err := c.SendProtobuf(c.entryPoint, &query, &result)
	if err != nil {
		return nil, err
	}

	log.Lvl1(c, "sent a query to the server.")
	queryID = result.QueryID
	return &queryID, nil
}

func (c *API) SendMultiplyQuery() {

}

func (c *API) GetWriteResult(id *QueryID) ([]byte, error) {
	log.Lvl1(c, "request result of write :", id)
	resp := ServiceResult{}
	err := c.SendProtobuf(c.entryPoint, &QueryResult{id, c.public}, &resp)
	if err != nil {
		return []byte{}, err
	}
	//todo ask if we need to have client <-> node encryption.
	//ideally yes
	data := resp.Data

	return data, nil
}

func (c *API) SendSetupQuery(entities *onet.Roster, generateEvaluationKey bool) error {
	log.Lvl1(c, "Sending a setup query to the roster")

	setupQuery := SetupRequest{*entities, generateEvaluationKey}
	resp := SetupReply{}
	err := c.SendProtobuf(c.entryPoint, &setupQuery, &resp)
	if err != nil {
		return err
	}

	log.Lvl1(c, " sent a setup request")
	return nil

}
