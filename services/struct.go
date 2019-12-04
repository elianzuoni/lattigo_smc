package services

import (
	"github.com/ldsec/lattigo/bfv"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/network"
)

const ServiceName = "LattigoSMC"

type ServiceState struct {
	QueryID QueryID
}

type ServiceResult struct {
	Data []byte
	//the restuls of a query encrypted with elgamal.
	K kyber.Point
	C kyber.Point
}

//The query for the result.
type QueryResult struct {
	QueryID *QueryID
	public  kyber.Point
}

//QueryData contains the information server side for the query.
type QueryData struct {
	QueryID      QueryID
	Roster       onet.Roster
	ClientPubKey kyber.Point
	Source       *network.ServerIdentity

	//what is in the query
	sum      bool
	multiply bool
	data     []byte
}

type SetupRequest struct {
	Roster onet.Roster

	GenerateEvaluationKey bool //it was available in gomomorphic hence it may have some uses.
}

//Query a query that a client can make to the service
type Query struct {
	bfv.Ciphertext
}

type StoreQuery struct {
	data []byte
	//maybe more is needed.
}
type SumQuery struct {
	amt uint32
}

type MultiplyQuery struct {
	amt uint32
}

type SetupReply struct {
	done int
}
