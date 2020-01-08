package services

import (
	"github.com/ldsec/lattigo/bfv"
	"go.dedis.ch/onet/v3"
	uuid "gopkg.in/satori/go.uuid.v1"
)

const ServiceName = "LattigoSMC"

type ServiceState struct {
	Id      uuid.UUID
	Pending bool
}

//The query for the result.
type QueryRemoteID struct {
	ID    uuid.UUID
	Local bool
}

type RemoteID struct {
	Local   uuid.UUID
	Remote  uuid.UUID
	Pending bool
}

//QueryData contains the information server side for the query.
type QueryData struct {
	Id     uuid.UUID
	Roster onet.Roster

	//what is in the query

	Data []byte
}

type SetupRequest struct {
	Roster onet.Roster

	ParamsIdx             uint64
	Seed                  []byte
	GenerateEvaluationKey bool
}

type KeyRequest struct {
	PublicKey     bool
	EvaluationKey bool
	RotationKey   bool
}

//KeyReply containing different requested keys.
type KeyReply struct {
	bfv.PublicKey
	//EvaluationKey bfv.EvaluationKey
	//RotationKeys bfv.RotationKeys

}

type StoreQuery struct {
	Ciphertext bfv.Ciphertext
	uuid.UUID
}

type StoreReply struct {
	Local  uuid.UUID
	Remote uuid.UUID
	Done   bool
}

type SumQuery struct {
	Id1 uuid.UUID
	Id2 uuid.UUID
}

type MultiplyQuery struct {
	Id1 uuid.UUID
	Id2 uuid.UUID
}

type SetupReply struct {
	Done int
}
