package services

import (
	"github.com/ldsec/lattigo/bfv"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/network"
	uuid "gopkg.in/satori/go.uuid.v1"
)

const ServiceName = "LattigoSMC"

type ServiceState struct {
	Id      uuid.UUID
	Pending bool
}

type ServiceResult struct {
	Data []byte
	//the restuls of a query encrypted with elgamal.
	K kyber.Point
	C kyber.Point
}

//The query for the result.
type QueryResult struct {
	Id     uuid.UUID
	public kyber.Point
}

//QueryData contains the information server side for the query.
type QueryData struct {
	Id           uuid.UUID
	Roster       onet.Roster
	ClientPubKey kyber.Point
	Source       *network.ServerIdentity

	//what is in the query
	Sum      bool
	Multiply bool
	Data     []byte
}

type SetupRequest struct {
	Roster onet.Roster

	ParamsIdx             uint64
	Seed                  []byte
	GenerateEvaluationKey bool
}

type StoreQuery struct {
	Id uuid.UUID
	bfv.Ciphertext
}

type StoreReply struct {
	Id   uuid.UUID
	Done bool
}

type SumQuery struct {
	Amt uint32
}

type MultiplyQuery struct {
	Amt uint32
}

type SetupReply struct {
	Done int
}
