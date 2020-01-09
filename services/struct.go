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

type RemoteID struct {
	Local   uuid.UUID
	Remote  uuid.UUID
	Pending bool
}

//QueryData contains the information server side for the query.
type QueryData struct {
	Roster onet.Roster
	//what is in the query
	Data []byte
	UUID uuid.UUID
}

type PlaintextReply struct {
	Data []byte
	uuid.UUID
}

type SetupRequest struct {
	Roster onet.Roster

	ParamsIdx             uint64
	Seed                  []byte
	GeneratePublicKey     bool
	GenerateEvaluationKey bool
	GenerateRotationKey   bool
	K                     uint64
	RotIdx                int
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
	Ciphertext *bfv.Ciphertext
	uuid.UUID
}

type StoreReply struct {
	Local  uuid.UUID
	Remote uuid.UUID
	Done   bool
}

//Sum UUID with Other
type SumQuery struct {
	UUID  uuid.UUID
	Other uuid.UUID
}

type SumReply struct {
	uuid.UUID
	SumQuery
}

//Multiply UUID with other
type MultiplyQuery struct {
	uuid.UUID
	Other uuid.UUID
}

//RefreshQuery query for UUID to be refreshed.
type RefreshQuery struct {
	uuid.UUID
}

//RelinQuery query for UUID to be relinearized
type RelinQuery struct {
	uuid.UUID
}

//SetupReply reply of the setup. if < 0 then it failed.
type SetupReply struct {
	Done int
}

//TODO discuss issue - its impossible to send this structure on the network. it says its BinaryMarshaller compliant but it only serializes the UUID nothing else.
//QueryPlaintext query for a ciphertext represented by UUID to be switched under publickey
type QueryPlaintext struct {
	PublicKey  *bfv.PublicKey
	Ciphertext *bfv.Ciphertext
	uuid.UUID
}

//ReplyPlaintext contains the ciphertext switched under the key requested.
type ReplyPlaintext struct {
	uuid.UUID
	Ciphertext *bfv.Ciphertext
}
