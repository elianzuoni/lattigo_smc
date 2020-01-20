//BinaryMarshaller implementation of structures.
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

func (mq *MultiplyQuery) MarshalBinary() ([]byte, error) {
	data := make([]byte, 32)
	copy(data[:uuid.Size], mq.UUID.Bytes())
	copy(data[uuid.Size:], mq.Other.Bytes())
	return data, nil
}

func (mq *MultiplyQuery) UnmarshalBinary(data []byte) error {
	if len(data) != 32 {
		return errors.New("unexpected data size")
	}
	err := mq.UUID.UnmarshalBinary(data[:uuid.Size])
	if err != nil {
		return err
	}
	err = mq.Other.UnmarshalBinary(data[uuid.Size:])
	return err
}

func (mr *MultiplyReply) MarshalBinary() ([]byte, error) {
	data, err := mr.MultiplyQuery.MarshalBinary()
	if err != nil {
		return []byte{}, err
	}
	data = append(data, mr.UUID.Bytes()...)
	return data, nil

}

func (mr *MultiplyReply) UnmarshalBinary(data []byte) error {
	err := mr.MultiplyQuery.UnmarshalBinary(data[:2*uuid.Size])
	if err != nil {
		return err
	}
	err = mr.UUID.UnmarshalBinary(data[2*uuid.Size:])
	return err
}

func (rq *RefreshQuery) MarshalBinary() ([]byte, error) {
	cast := new(ReplyPlaintext)

	cast.UUID = rq.UUID
	cast.Ciphertext = rq.Ciphertext
	data, err := cast.MarshalBinary()
	if err != nil {
		return []byte{}, err
	}
	var flag byte
	if rq.InnerQuery {
		flag = 1
	}
	data = append(data, flag)
	return data, nil
}

func (rq *RefreshQuery) UnmarshalBinary(data []byte) error {
	var cast ReplyPlaintext
	err := cast.UnmarshalBinary(data[:len(data)-1])
	if err != nil {
		return err
	}

	rq.UUID = cast.UUID
	rq.Ciphertext = cast.Ciphertext
	flag := data[len(data)-1]
	if flag > 0 {
		rq.InnerQuery = true
	} else {
		rq.InnerQuery = false
	}
	return nil
}

func (rr *RotationReply) MarshalBinary() ([]byte, error) {
	data := make([]byte, uuid.Size*2)
	oldD, err := rr.Old.MarshalBinary()
	if err != nil {
		return []byte{}, err
	}

	newD, err := rr.New.MarshalBinary()
	if err != nil {
		return []byte{}, err
	}

	copy(data[0:uuid.Size], oldD)
	copy(data[uuid.Size:], newD)
	return data, nil
}

func (rr *RotationReply) UnmarshalBinary(data []byte) error {
	if len(data) != uuid.Size*2 {
		return errors.New("unexpected data len have : " + string(len(data)) + " should be 32")
	}
	rr.Old = *new(uuid.UUID)
	err := rr.Old.UnmarshalBinary(data[:uuid.Size])
	if err != nil {
		return err
	}

	rr.New = *new(uuid.UUID)
	err = rr.New.UnmarshalBinary(data[uuid.Size:])
	return err
}

func (kr *KeyReply) MarshalBinary() ([]byte, error) {
	pkData := make([]byte, 0)
	var err error
	if kr.PublicKey != nil {
		pkData, err = kr.PublicKey.MarshalBinary()
		if err != nil {
			return []byte{}, err
		}

	}
	ekData := make([]byte, 0)
	if kr.EvaluationKey != nil {
		ekData, err = kr.EvaluationKey.MarshalBinary()
		if err != nil {
			return []byte{}, err
		}

	}

	rkData := make([]byte, 0)
	if kr.RotationKeys != nil {
		rkData, err = kr.RotationKeys.MarshalBinary()
		if err != nil {
			return []byte{}, err
		}

	}

	pkLen := len(pkData)
	ekLen := len(ekData)
	rkLen := len(rkData)
	data := make([]byte, pkLen+ekLen+rkLen+8*3+1)
	data[0] = byte(kr.RotIdx)
	pointer := 1
	binary.BigEndian.PutUint64(data[pointer:pointer+8], uint64(pkLen))
	pointer += 8
	binary.BigEndian.PutUint64(data[pointer:pointer+8], uint64(ekLen))
	pointer += 8
	binary.BigEndian.PutUint64(data[pointer:pointer+8], uint64(rkLen))
	pointer += 8
	copy(data[pointer:pointer+pkLen], pkData)
	pointer += pkLen
	copy(data[pointer:pointer+ekLen], ekData)
	pointer += ekLen
	copy(data[pointer:pointer+rkLen], rkData)
	pointer += rkLen

	return data, nil

}

func (kr *KeyReply) UnmarshalBinary(data []byte) error {
	if len(data) < 8*3+1 {
		return nil
	}
	kr.RotIdx = int(data[0])

	pointer := 1
	pkLen := int(binary.BigEndian.Uint64(data[pointer : pointer+8]))
	pointer += 8
	ekLen := int(binary.BigEndian.Uint64(data[pointer : pointer+8]))
	pointer += 8
	rkLen := int(binary.BigEndian.Uint64(data[pointer : pointer+8]))
	pointer += 8
	if pkLen > 0 {
		kr.PublicKey = new(bfv.PublicKey)
		err := kr.PublicKey.UnmarshalBinary(data[pointer : pointer+pkLen])
		if err != nil {
			return err
		}
		pointer += pkLen
	}

	if ekLen > 0 {
		kr.EvaluationKey = new(bfv.EvaluationKey)
		err := kr.EvaluationKey.UnmarshalBinary(data[pointer : pointer+ekLen])
		if err != nil {
			return err
		}
		pointer += ekLen
	}
	if rkLen > 0 {
		err := kr.RotationKeys.UnmarshalBinary(data[pointer : pointer+rkLen])
		if err != nil {
			return err
		}

		pointer += rkLen
	}

	return nil
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
