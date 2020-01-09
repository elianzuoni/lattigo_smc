package services

import (
	"encoding/binary"
	"errors"
	"github.com/ldsec/lattigo/bfv"
	uuid "gopkg.in/satori/go.uuid.v1"
)

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

	err := sq.UUID.UnmarshalBinary(data[pointer : pointer+uuid.Size])
	if err != nil {
		return err
	}

	return nil
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

	err := qp.UUID.UnmarshalBinary(data[pointer : pointer+uuid.Size])
	if err != nil {
		return err
	}

	return nil

}

func (rp *PlaintextReply) MarshalBinary() ([]byte, error) {
	data := make([]byte, len(rp.Data)+uuid.Size)
	copy(data[0:len(rp.Data)], rp.Data)
	id, err := rp.UUID.MarshalBinary()

	if err != nil {
		return []byte{}, err
	}
	copy(data[len(rp.Data):len(rp.Data)+uuid.Size], id)

	return data, nil
}

func (rp *PlaintextReply) UnmarshalBinary(data []byte) error {
	if len(data) < uuid.Size {
		return errors.New("insufficient data size")
	}
	lenData := len(data) - uuid.Size
	rp.Data = make([]byte, lenData)
	copy(rp.Data, data[:lenData])
	id := make([]byte, uuid.Size)
	copy(id, data[len(data)-uuid.Size:])
	err := rp.UUID.UnmarshalBinary(data[lenData:])
	return err
}

func (sq *SumQuery) MarshalBinary() ([]byte, error) {
	data := make([]byte, 32)
	copy(data[:uuid.Size], sq.UUID.Bytes())
	copy(data[uuid.Size:], sq.Other.Bytes())
	return data, nil
}

func (sq *SumQuery) UnmarshalBinary(data []byte) error {
	if len(data) != 32 {
		return errors.New("unexpected data size")
	}
	err := sq.UUID.UnmarshalBinary(data[:uuid.Size])
	if err != nil {
		return err
	}
	err = sq.Other.UnmarshalBinary(data[uuid.Size:])
	return err
}

func (sr *SumReply) MarshalBinary() ([]byte, error) {
	data, err := sr.SumQuery.MarshalBinary()
	if err != nil {
		return []byte{}, err
	}
	data = append(data, sr.UUID.Bytes()...)
	return data, nil

}

func (sr *SumReply) UnmarshalBinary(data []byte) error {
	err := sr.SumQuery.UnmarshalBinary(data[:2*uuid.Size])
	if err != nil {
		return err
	}
	err = sr.UUID.UnmarshalBinary(data[2*uuid.Size:])
	return err
}
