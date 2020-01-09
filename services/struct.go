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
	Ciphertext *bfv.Ciphertext
	uuid.UUID
}

func (sq *StoreQuery) MarshalBinary() ([]byte, error) {

	ctD := make([]byte, 0)
	if sq.Ciphertext != nil {
		ctD, _ = sq.Ciphertext.MarshalBinary()

	}

	idD, err := sq.UUID.MarshalBinary()
	if err != nil {
		return []byte{}, err
	}

	lenCt := len(ctD)
	lenidD := len(idD) // should be 16

	data := make([]byte, lenCt+lenidD+8*2) //last 16 bytes are for length of pk and ct
	pointer := 0

	binary.BigEndian.PutUint64(data[pointer:pointer+8], uint64(lenCt))
	pointer += 8

	copy(data[pointer:pointer+lenCt], ctD)
	pointer += lenCt
	copy(data[pointer:pointer+lenidD], idD)

	return data, nil
}
func (sq *StoreQuery) UnmarshalBinary(data []byte) error {
	pointer := 0
	lenCt := int(binary.BigEndian.Uint64(data[pointer : pointer+8]))
	pointer += 8

	if lenCt > 0 {
		sq.Ciphertext = new(bfv.Ciphertext)
		err := sq.Ciphertext.UnmarshalBinary(data[pointer : pointer+lenCt])
		if err != nil {
			return err
		}
	}

	pointer += lenCt

	err := sq.UUID.UnmarshalBinary(data[pointer : pointer+16])
	if err != nil {
		return err
	}

	return nil
}

type StoreReply struct {
	Local  uuid.UUID
	Remote uuid.UUID
	Done   bool
}

//Sum UUID with Other
type SumQuery struct {
	uuid.UUID
	Other uuid.UUID
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

func (qp *QueryPlaintext) MarshalBinary() ([]byte, error) {
	pkD := make([]byte, 0)
	if qp.PublicKey != nil {
		pkD, _ = qp.PublicKey.MarshalBinary()

	}

	ctD := make([]byte, 0)
	if qp.Ciphertext != nil {
		ctD, _ = qp.Ciphertext.MarshalBinary()

	}

	idD, err := qp.UUID.MarshalBinary()
	if err != nil {
		return []byte{}, err
	}

	lenPk := len(pkD)
	lenCt := len(ctD)
	lenidD := len(idD) // should be 16

	data := make([]byte, lenPk+lenCt+lenidD+8*2) //last 16 bytes are for length of pk and ct
	pointer := 0
	binary.BigEndian.PutUint64(data[pointer:pointer+8], uint64(lenPk))
	pointer += 8
	binary.BigEndian.PutUint64(data[pointer:pointer+8], uint64(lenCt))
	pointer += 8

	copy(data[pointer:pointer+lenPk], pkD)
	pointer += lenPk
	copy(data[pointer:pointer+lenCt], ctD)
	pointer += lenCt
	copy(data[pointer:pointer+lenidD], idD)

	return data, nil
}

func (qp *QueryPlaintext) UnmarshalBinary(data []byte) error {
	pointer := 0
	lenPk := int(binary.BigEndian.Uint64(data[pointer : pointer+8]))
	pointer += 8
	lenCt := int(binary.BigEndian.Uint64(data[pointer : pointer+8]))
	pointer += 8
	if lenPk > 0 {
		qp.PublicKey = new(bfv.PublicKey)
		err := qp.PublicKey.UnmarshalBinary(data[pointer : pointer+lenPk])
		if err != nil {
			return err
		}

	}

	pointer += lenPk
	if lenCt > 0 {
		qp.Ciphertext = new(bfv.Ciphertext)
		err := qp.Ciphertext.UnmarshalBinary(data[pointer : pointer+lenCt])
		if err != nil {
			return err
		}
	}

	pointer += lenCt

	err := qp.UUID.UnmarshalBinary(data[pointer : pointer+16])
	if err != nil {
		return err
	}

	return nil

}

//ReplyPlaintext contains the ciphertext switched under the key requested.
type ReplyPlaintext struct {
	uuid.UUID
	Ciphertext *bfv.Ciphertext
}

func (rp *ReplyPlaintext) MarshalBinary() ([]byte, error) {
	sq := StoreQuery{
		Ciphertext: rp.Ciphertext,
		UUID:       rp.UUID,
	}
	return sq.MarshalBinary()
}
func (rp *ReplyPlaintext) UnmarshalBinary(data []byte) error {
	var sq StoreQuery
	err := sq.UnmarshalBinary(data)
	if err != nil {
		return err
	}
	rp.UUID = sq.UUID
	rp.Ciphertext = sq.Ciphertext
	return nil
}
