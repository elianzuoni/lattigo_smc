package services

import (
	"github.com/ldsec/lattigo/bfv"
	"go.dedis.ch/onet/v3"
	uuid "gopkg.in/satori/go.uuid.v1"
)

const ServiceName = "LattigoSMC"

type SwitchingParameters struct {
	bfv.PublicKey
	bfv.Ciphertext
}

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

// KeyRequest is sent by client to server, and forwarded by server to root.
// Contains flag signalling which keys to retrieve.
type KeyRequest struct {
	PublicKey     bool
	EvaluationKey bool
	RotationKey   bool
	RotIdx        int
}

// KeyReply is sent by root to server, in response to KeyRequest.
// Contains the requested keys, if they exist.
type KeyReply struct {
	*bfv.PublicKey
	*bfv.EvaluationKey
	*bfv.RotationKeys
	RotIdx int
}

// StoreQuery is sent by server to root.
// Contains new ciphertext to store, and the original UUID (generated by the server)
type StoreQuery struct {
	Ciphertext *bfv.Ciphertext
	uuid.UUID
}

// StoreReply is sent by root to server, in response to StoreQuery.
// Contains the original UUID sent with the query, and the fresh UUID generated by the root
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

type MultiplyReply struct {
	uuid.UUID
	MultiplyQuery
}

//RefreshQuery query for UUID to be refreshed.
type RefreshQuery struct {
	uuid.UUID
	InnerQuery bool
	*bfv.Ciphertext
}

//RelinQuery query for UUID to be relinearized
type RelinQuery struct {
	uuid.UUID
}

//SetupReply reply of the setup. if < 0 then it failed.
type SetupReply struct {
	Done int
}

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

type RotationQuery struct {
	uuid.UUID
	K      uint64
	RotIdx int
}

type RotationReply struct {
	Old uuid.UUID
	New uuid.UUID
}
