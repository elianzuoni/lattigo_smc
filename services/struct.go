package services

import (
	"encoding/binary"
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
	RotIdx        int
}

//KeyReply containing different requested keys.
type KeyReply struct {
	*bfv.PublicKey
	*bfv.EvaluationKey
	*bfv.RotationKeys
	RotIdx int
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

type MultiplyReply struct {
	uuid.UUID
	MultiplyQuery
}

//RefreshQuery query for UUID to be refreshed.
type RefreshQuery struct {
	uuid.UUID
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

func (rq *RotationQuery) MarshalBinary() ([]byte, error) {
	data := make([]byte, uuid.Size+1+8)
	id, err := rq.UUID.MarshalBinary()
	if err != nil {
		return []byte{}, err
	}
	ptr := 0
	copy(data[ptr:ptr+uuid.Size], id)
	ptr += uuid.Size
	binary.BigEndian.PutUint64(data[ptr:ptr+8], rq.K)
	ptr += 8
	data[ptr] = byte(rq.RotIdx)
	return data, nil

}

func (rq *RotationQuery) UnmarshalBinary(data []byte) error {
	err := rq.UUID.UnmarshalBinary(data[:uuid.Size])
	ptr := uuid.Size
	rq.K = binary.BigEndian.Uint64(data[ptr : ptr+8])
	ptr += 8
	rq.RotIdx = int(data[ptr])
	return err
}

type RotationReply struct {
	Old uuid.UUID
	New uuid.UUID
}
