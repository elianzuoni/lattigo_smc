// BinaryMarshaller implementation of message structures.

package service

/*

import (
	"encoding/binary"
	uuid "gopkg.in/satori/go.uuid.v1"
)

// TODO: is this needed?
func marshBool(b bool) byte {
	if b {
		return byte(1)
	}
	return byte(0)
}
func unmarshBool(b byte) bool {
	return b == byte(1)
}
func marshUUID(u uuid.UUID) ([]byte, error) {
	return (&u).MarshalBinary()
}
func unmarshUUID(data []byte) (u uuid.UUID, err error) {
	err = (&u).UnmarshalBinary(data)
	return
}

// Setup




func (query *SetupQuery) MarshalBinary() (data []byte, err error) {
	// TODO: how to marshal roster?
	return
}

func (query *SetupQuery) UnmarshalBinary(data []byte) (err error) {
	// TODO: how to unmarshal roster?
	return
}

func (req *SetupRequest) MarshalBinary() (data []byte, err error) {
	// Marshal RequestID
	idData, err := marshUUID((uuid.UUID)(req.SetupRequestID))
	if err != nil {
		return
	}
	idLen := len(idData)

	// Marshal SetupQuery
	queryData := make([]byte, 0)
	if req.SetupQuery != nil {
		queryData, err = req.SetupQuery.MarshalBinary()
		if err != nil {
			return
		}
	}
	queryLen := len(queryData)

	// Build data as [<idLen>, <queryLen>, <RequestID>, <SetupQuery>]
	data = make([]byte, 8+8+idLen+queryLen)
	ptr := 0 // Used to index data
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(idLen))
	ptr += 8
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(queryLen))
	ptr += 8
	copy(data[ptr:ptr+idLen], idData)
	ptr += idLen
	copy(data[ptr:ptr+queryLen], queryData)
	ptr += queryLen

	return
}


func (req *SetupRequest) UnmarshalBinary(data []byte) (err error) {
	ptr := 0 // Used to index data

	// Read lengths
	idLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8
	queryLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8

	// Read fields
	if idLen > 0 {
		var id uuid.UUID
		id, err = unmarshUUID(data[ptr : ptr+idLen])
		req.SetupRequestID = (SetupRequestID)(id)
		ptr += idLen
		if err != nil {
			return
		}
	} // TODO: else?
	if queryLen > 0 {
		err = req.SetupQuery.UnmarshalBinary(data[ptr : ptr+queryLen])
		ptr += queryLen
		if err != nil {
			return
		}
	} // TODO: else?

	return
}

func (prep *SetupBroadcast) MarshalBinary() (data []byte, err error) {
	data, err = (*SetupRequest)(prep).MarshalBinary()

	return
}

func (prep *SetupBroadcast) UnmarshalBinary(data []byte) (err error) {
	err = (*SetupRequest)(prep).UnmarshalBinary(data) // TODO: does this work?

	return
}

func (reply *SetupReply) MarshalBinary() (data []byte, err error) {
	// Marshal RequestID
	idData, err := marshUUID((uuid.UUID)(reply.SetupRequestID))
	if err != nil {
		return
	}
	idLen := len(idData)

	// Transform the rest to a Response, then marshal it
	resp := &SetupResponse{reply.pubKeyGenerated, reply.evalKeyGenerated,
		reply.rotKeyGenerated}
	respData, _ := resp.MarshalBinary() // We know it won't return error
	// We know the length is 3

	// Build data as [<idLen>, <RequestID>, <SetupResponse>]
	data = make([]byte, 8+idLen+3)
	ptr := 0 // Used to index data
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(idLen))
	ptr += 8
	copy(data[ptr:ptr+idLen], idData)
	ptr += idLen
	copy(data[ptr:ptr+3], respData)
	ptr += 3

	return
}

func (reply *SetupReply) UnmarshalBinary(data []byte) (err error) {
	ptr := 0 // Used to index data

	// Read length
	idLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8

	// Read fields
	if idLen > 0 {
		var id uuid.UUID
		id, err = unmarshUUID(data[ptr : ptr+idLen])
		reply.SetupRequestID = (SetupRequestID)(id)
		ptr += idLen
		if err != nil {
			return
		}
	} // TODO: else?
	resp := &SetupResponse{}
	_ = resp.UnmarshalBinary(data[ptr : ptr+3]) // We know it won't return error
	reply.pubKeyGenerated = resp.PubKeyGenerated
	reply.evalKeyGenerated = resp.EvalKeyGenerated
	reply.rotKeyGenerated = resp.RotKeyGenerated

	return
}

func (resp *SetupResponse) MarshalBinary() (data []byte, err error) {
	// Directly build data as [<genPK>, <genEvK>, <genRtK>]
	data = make([]byte, 1+1+1)
	data[0] = marshBool(resp.PubKeyGenerated)
	data[1] = marshBool(resp.EvalKeyGenerated)
	data[2] = marshBool(resp.RotKeyGenerated)

	return
}

func (resp *SetupResponse) UnmarshalBinary(data []byte) (err error) {
	// Directly read fields
	resp.PubKeyGenerated = unmarshBool(data[0])
	resp.EvalKeyGenerated = unmarshBool(data[1])
	resp.RotKeyGenerated = unmarshBool(data[2])

	return
}



// Key

func (query *KeyQuery) MarshalBinary() (data []byte, err error) {
	// Directly build data as [<getPK>, <getEvK>, <getRtK>, <rotIdX>]
	data = make([]byte, 1+1+1+1) // rotIdX, though it is an int, ban be written on a byte
	data[0] = marshBool(query.PublicKey)
	data[1] = marshBool(query.EvaluationKey)
	data[2] = marshBool(query.RotationKey)
	data[3] = byte(query.RotIdx)

	return
}

func (query *KeyQuery) UnmarshalBinary(data []byte) (err error) {
	// Directly read fields
	query.PublicKey = unmarshBool(data[0])
	query.EvaluationKey = unmarshBool(data[1])
	query.RotationKey = unmarshBool(data[2])
	query.RotIdx = int(data[3])

	return
}

func (req *KeyRequest) MarshalBinary() (data []byte, err error) {
	// Marshal RequestID
	idData, err := marshUUID((uuid.UUID)(req.KeyRequestID))
	if err != nil {
		return
	}
	idLen := len(idData)

	// Marshal KeyQuery
	queryData := make([]byte, 0)
	if req.KeyQuery != nil {
		queryData, _ = req.KeyQuery.MarshalBinary() // We know it won't return error
	}
	// We know the length is 4

	// Build data as [<idLen>, <RequestID>, <SetupQuery>]
	data = make([]byte, 8+idLen+4)
	ptr := 0 // Used to index data
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(idLen))
	ptr += 8
	copy(data[ptr:ptr+idLen], idData)
	ptr += idLen
	copy(data[ptr:ptr+4], queryData)
	ptr += 4

	return
}

func (req *KeyRequest) UnmarshalBinary(data []byte) (err error) {
	ptr := 0 // Used to index data

	// Read lengths
	idLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8
	queryLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8

	// Read fields
	if idLen > 0 {
		var id uuid.UUID
		id, err = unmarshUUID(data[ptr : ptr+idLen])
		req.KeyRequestID = (KeyRequestID)(id)
		ptr += idLen
		if err != nil {
			return
		}
	} // TODO: else?
	if queryLen > 0 {
		err = req.KeyQuery.UnmarshalBinary(data[ptr : ptr+queryLen])
		ptr += queryLen
		if err != nil {
			return
		}
	} // TODO: else?

	return
}

func (reply *KeyReply) MarshalBinary() (data []byte, err error) {
	// Marshal RequestID
	idData, err := marshUUID((uuid.UUID)(reply.KeyRequestID))
	if err != nil {
		return
	}
	idLen := len(idData)

	// Marshal pk
	pkData := make([]byte, 0)
	if reply.pk != nil {
		pkData, err = reply.pk.MarshalBinary()
		if err != nil {
			return
		}
	}
	pkLen := len(pkData)

	// Marshal evk
	evkData := make([]byte, 0)
	if reply.pk != nil {
		evkData, err = reply.evk.MarshalBinary()
		if err != nil {
			return
		}
	}
	evkLen := len(evkData)

	// Marshal rtk
	rtkData := make([]byte, 0)
	if reply.pk != nil {
		rtkData, err = reply.rtk.MarshalBinary()
		if err != nil {
			return
		}
	}
	rtkLen := len(rtkData)

	// Build data as [<idLen>, <pkLen>, <evkLen>, <rtkLen>, <RequestID>, <pk>, <evk>, <rtk>, <rotIdx>]
	data = make([]byte, 8+8+8+8+idLen+pkLen+evkLen+rtkLen+1)
	ptr := 0 // Used to index data
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(idLen))
	ptr += 8
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(pkLen))
	ptr += 8
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(evkLen))
	ptr += 8
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(rtkLen))
	ptr += 8
	copy(data[ptr:ptr+idLen], idData)
	ptr += idLen
	copy(data[ptr:ptr+pkLen], pkData)
	ptr += pkLen
	copy(data[ptr:ptr+evkLen], evkData)
	ptr += evkLen
	copy(data[ptr:ptr+rtkLen], rtkData)
	ptr += rtkLen
	data[ptr] = byte(reply.RotIdx)
	ptr += 1

	return
}

func (reply *KeyReply) UnmarshalBinary(data []byte) (err error) {
	ptr := 0 // Used to index data

	// Read lengths
	idLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8
	pkLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8
	evkLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8
	rtkLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8

	// Read fields
	if idLen > 0 {
		var id uuid.UUID
		id, err = unmarshUUID(data[ptr : ptr+idLen])
		reply.KeyRequestID = (KeyRequestID)(id)
		ptr += idLen
		if err != nil {
			return
		}
	} // TODO: else?
	if pkLen > 0 {
		err = reply.pk.UnmarshalBinary(data[ptr : ptr+pkLen])
		ptr += pkLen
		if err != nil {
			return
		}
	} // TODO: else?
	if evkLen > 0 {
		err = reply.evk.UnmarshalBinary(data[ptr : ptr+evkLen])
		ptr += evkLen
		if err != nil {
			return
		}
	} // TODO: else?
	if rtkLen > 0 {
		err = reply.rtk.UnmarshalBinary(data[ptr : ptr+rtkLen])
		ptr += idLen
		if err != nil {
			return
		}
	} // TODO: else?
	reply.RotIdx = int(data[ptr])
	ptr += 1

	return
}

func (resp *KeyResponse) MarshalBinary() (data []byte, err error) {
	// Directly build data as [<gotPK>, <gotEvK>, <gotRtK>]
	data = make([]byte, 1+1+1)
	data[0] = marshBool(resp.PubKeyObtained)
	data[1] = marshBool(resp.EvalKeyObtained)
	data[2] = marshBool(resp.RotKeyObtained)

	return
}

func (resp *KeyResponse) UnmarshalBinary(data []byte) (err error) {
	// Directly read fields
	resp.PubKeyObtained = unmarshBool(data[0])
	resp.EvalKeyObtained = unmarshBool(data[1])
	resp.RotKeyObtained = unmarshBool(data[3])

	return
}

// Store

func (query *StoreQuery) MarshalBinary() (data []byte, err error) {
	// Marshal Ciphertext
	ctData := make([]byte, 0)
	if query.Ciphertext != nil {
		ctData, err = query.Ciphertext.MarshalBinary()
		if err != nil {
			return
		}
	}
	ctLen := len(ctData)

	// Build data as [<ctLen>, <Ciphertext>]
	data = make([]byte, 8+ctLen)
	ptr := 0 // Used to index data
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(ctLen))
	ptr += 8
	copy(data[ptr:ptr+ctLen], ctData)
	ptr += ctLen

	return
}

func (query *StoreQuery) UnmarshalBinary(data []byte) (err error) {
	ptr := 0 // Used to index data

	// Read length
	ctLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8

	// Read Ciphertext
	if ctLen > 0 {
		err = query.Ciphertext.UnmarshalBinary(data[ptr : ptr+ctLen])
		ptr += ctLen
		if err != nil {
			return
		}
	} // TODO: else?

	return
}

func (req *StoreRequest) MarshalBinary() (data []byte, err error) {
	// Marshal RequestID
	idData, err := marshUUID((uuid.UUID)(req.StoreRequestID))
	if err != nil {
		return
	}
	idLen := len(idData)

	// Marshal StoreQuery
	queryData := make([]byte, 0)
	if req.StoreQuery != nil {
		queryData, err = req.StoreQuery.MarshalBinary()
		if err != nil {
			return
		}
	}
	queryLen := len(queryData)

	// Build data as [<idLen>, <queryLen>, <RequestID>, <SetupQuery>]
	data = make([]byte, 8+8+idLen+queryLen)
	ptr := 0 // Used to index data
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(idLen))
	ptr += 8
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(queryLen))
	ptr += 8
	copy(data[ptr:ptr+idLen], idData)
	ptr += idLen
	copy(data[ptr:ptr+queryLen], queryData)
	ptr += queryLen

	return
}

func (req *StoreRequest) UnmarshalBinary(data []byte) (err error) {
	ptr := 0 // Used to index data

	// Read lengths
	idLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8
	queryLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8

	// Read fields
	if idLen > 0 {
		var id uuid.UUID
		id, err = unmarshUUID(data[ptr : ptr+idLen])
		req.StoreRequestID = (StoreRequestID)(id)
		ptr += idLen
		if err != nil {
			return
		}
	} // TODO: else?
	if queryLen > 0 {
		err = req.StoreQuery.UnmarshalBinary(data[ptr : ptr+queryLen])
		ptr += queryLen
		if err != nil {
			return
		}
	} // TODO: else?

	return
}

func (reply *StoreReply) MarshalBinary() (data []byte, err error) {
	// Marshal RequestID
	idData, err := marshUUID((uuid.UUID)(reply.StoreRequestID))
	if err != nil {
		return
	}
	idLen := len(idData)

	// Marshal CipherID
	ctIdData, err := marshUUID((uuid.UUID)(reply.cipherID))
	if err != nil {
		return
	}
	ctIdLen := len(ctIdData)

	// Build data as [<idLen>, <ctIdLen>, <RequestID>, <CipherID>]
	data = make([]byte, 8+8+idLen+ctIdLen)
	ptr := 0 // Used to index data
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(idLen))
	ptr += 8
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(ctIdLen))
	ptr += 8
	copy(data[ptr:ptr+idLen], idData)
	ptr += idLen
	copy(data[ptr:ptr+ctIdLen], ctIdData)
	ptr += ctIdLen

	return
}

func (reply *StoreReply) UnmarshalBinary(data []byte) (err error) {
	ptr := 0 // Used to index data

	// Read lengths
	idLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8
	ctIdLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8

	// Read fields
	if idLen > 0 {
		var id uuid.UUID
		id, err = unmarshUUID(data[ptr : ptr+idLen])
		reply.StoreRequestID = (StoreRequestID)(id)
		ptr += idLen
		if err != nil {
			return
		}
	} // TODO: else?
	if ctIdLen > 0 {
		var id uuid.UUID
		id, err = unmarshUUID(data[ptr : ptr+ctIdLen])
		reply.cipherID = (CipherID)(id)
		ptr += ctIdLen
		if err != nil {
			return
		}
	} // TODO: else?

	return
}

func (resp *StoreResponse) MarshalBinary() (data []byte, err error) {
	// Marshal CipherID
	ctIdData, err := marshUUID((uuid.UUID)(resp.CipherID))
	if err != nil {
		return
	}
	ctIdLen := len(ctIdData)

	// Build data as [<ctIdLen>, <CipherID>]
	data = make([]byte, 8+ctIdLen)
	ptr := 0 // Used to index data
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(ctIdLen))
	ptr += 8
	copy(data[ptr:ptr+ctIdLen], ctIdData)
	ptr += ctIdLen

	return
}

func (resp *StoreResponse) UnmarshalBinary(data []byte) (err error) {
	ptr := 0 // Used to index data

	// Read lengths
	ctIdLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8

	// Read fields
	if ctIdLen > 0 {
		var id uuid.UUID
		id, err = unmarshUUID(data[ptr : ptr+ctIdLen])
		resp.CipherID = (CipherID)(id)
		ptr += ctIdLen
		if err != nil {
			return
		}
	} // TODO: else?

	return
}

// Retrieve

func (query *RetrieveQuery) MarshalBinary() (data []byte, err error) {
	// Marshal CipherID
	ctIdData, err := marshUUID((uuid.UUID)(query.CipherID))
	if err != nil {
		return
	}
	ctIdLen := len(ctIdData)

	// Marshal PublicKey
	pkData := make([]byte, 0)
	if query.PublicKey != nil {
		pkData, err = query.PublicKey.MarshalBinary()
		if err != nil {
			return
		}
	}
	pkLen := len(pkData)

	// Build data as [<ctIdLen>, <pkLen>, <CipherID>, <PublicKey>]
	data = make([]byte, 8+8+ctIdLen+pkLen)
	ptr := 0 // Used to index data
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(ctIdLen))
	ptr += 8
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(pkLen))
	ptr += 8
	copy(data[ptr:ptr+ctIdLen], ctIdData)
	ptr += ctIdLen
	copy(data[ptr:ptr+pkLen], pkData)
	ptr += pkLen

	return
}

func (query *RetrieveQuery) UnmarshalBinary(data []byte) (err error) {
	ptr := 0 // Used to index data

	// Read lengths
	ctIdLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8
	pkLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8

	// Read fields
	if ctIdLen > 0 {
		var id uuid.UUID
		id, err = unmarshUUID(data[ptr : ptr+ctIdLen])
		query.CipherID = (CipherID)(id)
		ptr += ctIdLen
		if err != nil {
			return
		}
	} // TODO: else?
	if pkLen > 0 {
		err = query.PublicKey.UnmarshalBinary(data[ptr : ptr+pkLen])
		ptr += pkLen
		if err != nil {
			return
		}
	} // TODO: else?

	return
}

func (req *RetrieveRequest) MarshalBinary() (data []byte, err error) {
	// Marshal RequestID
	idData, err := marshUUID((uuid.UUID)(req.RetrieveRequestID))
	if err != nil {
		return
	}
	idLen := len(idData)

	// Marshal SetupQuery
	queryData := make([]byte, 0)
	if req.RetrieveQuery != nil {
		queryData, err = req.RetrieveQuery.MarshalBinary()
		if err != nil {
			return
		}
	}
	queryLen := len(queryData)

	// Build data as [<idLen>, <queryLen>, <RequestID>, <RetrieveQuery>]
	data = make([]byte, 8+8+idLen+queryLen)
	ptr := 0 // Used to index data
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(idLen))
	ptr += 8
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(queryLen))
	ptr += 8
	copy(data[ptr:ptr+idLen], idData)
	ptr += idLen
	copy(data[ptr:ptr+queryLen], queryData)
	ptr += queryLen

	return
}

func (req *RetrieveRequest) UnmarshalBinary(data []byte) (err error) {
	ptr := 0 // Used to index data

	// Read lengths
	idLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8
	queryLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8

	// Read fields
	if idLen > 0 {
		var id uuid.UUID
		id, err = unmarshUUID(data[ptr : ptr+idLen])
		req.RetrieveRequestID = (RetrieveRequestID)(id)
		ptr += idLen
		if err != nil {
			return
		}
	} // TODO: else?
	if queryLen > 0 {
		err = req.RetrieveQuery.UnmarshalBinary(data[ptr : ptr+queryLen])
		ptr += queryLen
		if err != nil {
			return
		}
	} // TODO: else?

	return
}

func (params *SwitchingParameters) MarshalBinary() (data []byte, err error) {
	// Marshal Ciphertext
	ctData := make([]byte, 0)
	if params.Ciphertext != nil {
		ctData, err = params.Ciphertext.MarshalBinary()
		if err != nil {
			return
		}
	}
	ctLen := len(ctData)

	// Marshal PublicKey
	pkData := make([]byte, 0)
	if params.PublicKey != nil {
		pkData, err = params.PublicKey.MarshalBinary()
		if err != nil {
			return
		}
	}
	pkLen := len(pkData)

	// Build data as [<ctLen>, <pkLen>, <Ciphertext>, <PublicKey>]
	data = make([]byte, 8+8+ctLen+pkLen)
	ptr := 0 // Used to index data
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(ctLen))
	ptr += 8
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(pkLen))
	ptr += 8
	copy(data[ptr:ptr+ctLen], ctData)
	ptr += ctLen
	copy(data[ptr:ptr+pkLen], pkData)
	ptr += pkLen

	return
}

func (params *SwitchingParameters) UnmarshalBinary(data []byte) (err error) {
	ptr := 0 // Used to index data

	// Read lengths
	ctLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8
	pkLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8

	// Read fields
	if ctLen > 0 {
		err = params.Ciphertext.UnmarshalBinary(data[ptr : ptr+ctLen])
		ptr += ctLen
		if err != nil {
			return
		}
	} // TODO: else?
	if pkLen > 0 {
		err = params.PublicKey.UnmarshalBinary(data[ptr : ptr+pkLen])
		ptr += pkLen
		if err != nil {
			return
		}
	} // TODO: else?

	return
}

func (prep *RetrieveBroadcast) MarshalBinary() (data []byte, err error) {
	// Marshal RequestID
	idData, err := marshUUID((uuid.UUID)(prep.RetrieveRequestID))
	if err != nil {
		return
	}
	idLen := len(idData)

	// Marshal SwitchingParameters
	paramsData := make([]byte, 0)
	if prep.params != nil {
		paramsData, err = prep.params.MarshalBinary()
		if err != nil {
			return
		}
	}
	paramsLen := len(paramsData)

	// Build data as [<idLen>, <paramsLen>, <RequestID>, <SwitchingParameters>]
	data = make([]byte, 8+8+idLen+paramsLen)
	ptr := 0 // Used to index data
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(idLen))
	ptr += 8
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(paramsLen))
	ptr += 8
	copy(data[ptr:ptr+idLen], idData)
	ptr += idLen
	copy(data[ptr:ptr+paramsLen], paramsData)
	ptr += paramsLen

	return
}

func (prep *RetrieveBroadcast) UnmarshalBinary(data []byte) (err error) {
	ptr := 0 // Used to index data

	// Read lengths
	idLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8
	paramsLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8

	// Read fields
	if idLen > 0 {
		var id uuid.UUID
		id, err = unmarshUUID(data[ptr : ptr+idLen])
		prep.RetrieveRequestID = (RetrieveRequestID)(id)
		ptr += idLen
		if err != nil {
			return
		}
	} // TODO: else?
	if paramsLen > 0 {
		err = prep.params.UnmarshalBinary(data[ptr : ptr+paramsLen])
		ptr += paramsLen
		if err != nil {
			return
		}
	} // TODO: else?

	return
}

func (reply *RetrieveReply) MarshalBinary() (data []byte, err error) {
	// Marshal RequestID
	idData, err := marshUUID((uuid.UUID)(reply.RetrieveRequestID))
	if err != nil {
		return
	}
	idLen := len(idData)

	// Transform the rest to a Response, then marshal it
	resp := &RetrieveResponse{reply.ciphertext, reply.valid}
	respData, err := resp.MarshalBinary()
	if err != nil {
		return
	}
	respLen := len(respData)

	// Build data as [<idLen>, <respLen>, <RequestID>, <RetrieveResponse>]
	data = make([]byte, 8+8+idLen+respLen)
	ptr := 0 // Used to index data
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(idLen))
	ptr += 8
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(respLen))
	ptr += 8
	copy(data[ptr:ptr+idLen], idData)
	ptr += idLen
	copy(data[ptr:ptr+respLen], respData)
	ptr += respLen

	return
}

func (reply *RetrieveReply) UnmarshalBinary(data []byte) (err error) {
	ptr := 0 // Used to index data

	// Read lengths
	idLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8
	respLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8

	// Read fields
	if idLen > 0 {
		var id uuid.UUID
		id, err = unmarshUUID(data[ptr : ptr+idLen])
		reply.RetrieveRequestID = (RetrieveRequestID)(id)
		ptr += idLen
		if err != nil {
			return
		}
	} // TODO: else?
	if respLen > 0 {
		resp := &RetrieveResponse{}
		err = resp.UnmarshalBinary(data[ptr : ptr+respLen])
		ptr += respLen
		if err != nil {
			return
		}

		reply.ciphertext = resp.Ciphertext
		reply.valid = resp.Valid
	} // TODO: else?

	return
}

func (resp *RetrieveResponse) MarshalBinary() (data []byte, err error) {
	// Marshal Ciphertext
	ctData := make([]byte, 0)
	if resp.Ciphertext != nil {
		ctData, err = resp.Ciphertext.MarshalBinary()
		if err != nil {
			return
		}
	}
	ctLen := len(ctData)

	// Build data as [<ctLen>, <Ciphertext>, <Valid>]
	data = make([]byte, 8+ctLen+1)
	ptr := 0 // Used to index data
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(ctLen))
	ptr += 8
	copy(data[ptr:ptr+ctLen], ctData)
	ptr += ctLen
	data[ptr] = marshBool(resp.Valid)
	ptr += 1

	return
}

func (resp *RetrieveResponse) UnmarshalBinary(data []byte) (err error) {
	ptr := 0 // Used to index data

	// Read length
	ctLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8

	// Read fields
	if ctLen > 0 {
		err = resp.Ciphertext.UnmarshalBinary(data[ptr : ptr+ctLen])
		ptr += ctLen
		if err != nil {
			return
		}
	} // TODO: else?
	resp.Valid = unmarshBool(data[ptr])
	ptr += 1

	return
}

// Sum

func (query *SumQuery) MarshalBinary() (data []byte, err error) {
	// Marshal CipherID1
	ctId1Data, err := marshUUID((uuid.UUID)(query.CipherID1))
	if err != nil {
		return
	}
	ctId1Len := len(ctId1Data)

	// Marshal CipherID2
	ctId2Data, err := marshUUID((uuid.UUID)(query.CipherID2))
	if err != nil {
		return
	}
	ctId2Len := len(ctId2Data)

	// Build data as [<ctId1Len>, <ctId2Len>, <CipherID1>, <CipherID2>]
	data = make([]byte, 8+8+ctId1Len+ctId2Len)
	ptr := 0 // Used to index data
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(ctId1Len))
	ptr += 8
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(ctId2Len))
	ptr += 8
	copy(data[ptr:ptr+ctId1Len], ctId1Data)
	ptr += ctId1Len
	copy(data[ptr:ptr+ctId2Len], ctId2Data)
	ptr += ctId2Len

	return
}

func (query *SumQuery) UnmarshalBinary(data []byte) (err error) {
	ptr := 0 // Used to index data

	// Read lengths
	ctId1Len := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8
	ctId2Len := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8

	// Read fields
	if ctId1Len > 0 {
		var id uuid.UUID
		id, err = unmarshUUID(data[ptr : ptr+ctId1Len])
		query.CipherID1 = (CipherID)(id)
		ptr += ctId1Len
		if err != nil {
			return
		}
	} // TODO: else?
	if ctId2Len > 0 {
		var id uuid.UUID
		id, err = unmarshUUID(data[ptr : ptr+ctId2Len])
		query.CipherID2 = (CipherID)(id)
		ptr += ctId2Len
		if err != nil {
			return
		}
	} // TODO: else?

	return
}

func (req *SumRequest) MarshalBinary() (data []byte, err error) {
	// Marshal RequestID
	idData, err := marshUUID((uuid.UUID)(req.SumRequestID))
	if err != nil {
		return
	}
	idLen := len(idData)

	// Marshal SumQuery
	queryData := make([]byte, 0)
	if req.SumQuery != nil {
		queryData, err = req.SumQuery.MarshalBinary()
		if err != nil {
			return
		}
	}
	queryLen := len(queryData)

	// Build data as [<idLen>, <queryLen>, <RequestID>, <SumQuery>]
	data = make([]byte, 8+8+idLen+queryLen)
	ptr := 0 // Used to index data
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(idLen))
	ptr += 8
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(queryLen))
	ptr += 8
	copy(data[ptr:ptr+idLen], idData)
	ptr += idLen
	copy(data[ptr:ptr+queryLen], queryData)
	ptr += queryLen

	return
}

func (req *SumRequest) UnmarshalBinary(data []byte) (err error) {
	ptr := 0 // Used to index data

	// Read lengths
	idLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8
	queryLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8

	// Read fields
	if idLen > 0 {
		var id uuid.UUID
		id, err = unmarshUUID(data[ptr : ptr+idLen])
		req.SumRequestID = (SumRequestID)(id)
		ptr += idLen
		if err != nil {
			return
		}
	} // TODO: else?
	if queryLen > 0 {
		err = req.SumQuery.UnmarshalBinary(data[ptr : ptr+queryLen])
		ptr += queryLen
		if err != nil {
			return
		}
	} // TODO: else?

	return
}

func (reply *SumReply) MarshalBinary() (data []byte, err error) {
	// Marshal RequestID
	idData, err := marshUUID((uuid.UUID)(reply.SumRequestID))
	if err != nil {
		return
	}
	idLen := len(idData)

	// Transform the rest to a Response, then marshal it
	resp := &SumResponse{reply.newCipherID, reply.valid}
	respData, err := resp.MarshalBinary()
	if err != nil {
		return
	}
	respLen := len(respData)

	// Build data as [<idLen>, <respLen>, <RequestID>, <SumResponse>]
	data = make([]byte, 8+8+idLen+respLen)
	ptr := 0 // Used to index data
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(idLen))
	ptr += 8
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(respLen))
	ptr += 8
	copy(data[ptr:ptr+idLen], idData)
	ptr += idLen
	copy(data[ptr:ptr+respLen], respData)
	ptr += respLen

	return
}

func (reply *SumReply) UnmarshalBinary(data []byte) (err error) {
	ptr := 0 // Used to index data

	// Read lengths
	idLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8
	respLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8

	// Read fields
	if idLen > 0 {
		var id uuid.UUID
		id, err = unmarshUUID(data[ptr : ptr+idLen])
		reply.SumRequestID = (SumRequestID)(id)
		ptr += idLen
		if err != nil {
			return
		}
	} // TODO: else?
	if respLen > 0 {
		resp := &SumResponse{}
		err = resp.UnmarshalBinary(data[ptr : ptr+respLen])
		ptr += respLen
		if err != nil {
			return
		}

		reply.newCipherID = resp.NewCipherID
		reply.valid = resp.Valid
	} // TODO: else?

	return
}

func (resp *SumResponse) MarshalBinary() (data []byte, err error) {
	// Marshal CipherID
	ctIdData, err := marshUUID((uuid.UUID)(resp.NewCipherID))
	if err != nil {
		return
	}
	ctIdLen := len(ctIdData)

	// Build data as [<ctIdLen>, <NewCipherID>, <Valid>]
	data = make([]byte, 8+ctIdLen+1)
	ptr := 0 // Used to index data
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(ctIdLen))
	ptr += 8
	copy(data[ptr:ptr+ctIdLen], ctIdData)
	ptr += ctIdLen
	data[ptr] = marshBool(resp.Valid)
	ptr += 1

	return
}

func (resp *SumResponse) UnmarshalBinary(data []byte) (err error) {
	ptr := 0 // Used to index data

	// Read length
	ctIdLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8

	// Read fields
	if ctIdLen > 0 {
		var id uuid.UUID
		id, err = unmarshUUID(data[ptr : ptr+ctIdLen])
		resp.NewCipherID = (CipherID)(id)
		ptr += ctIdLen
		if err != nil {
			return
		}
	} // TODO: else?
	resp.Valid = unmarshBool(data[ptr])
	ptr += 1

	return
}

// Multiply

func (query *MultiplyQuery) MarshalBinary() (data []byte, err error) {
	// Marshal CipherID1
	ctId1Data, err := marshUUID((uuid.UUID)(query.CipherID1))
	if err != nil {
		return
	}
	ctId1Len := len(ctId1Data)

	// Marshal CipherID2
	ctId2Data, err := marshUUID((uuid.UUID)(query.CipherID2))
	if err != nil {
		return
	}
	ctId2Len := len(ctId2Data)

	// Build data as [<ctId1Len>, <ctId2Len>, <CipherID1>, <CipherID2>]
	data = make([]byte, 8+8+ctId1Len+ctId2Len)
	ptr := 0 // Used to index data
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(ctId1Len))
	ptr += 8
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(ctId2Len))
	ptr += 8
	copy(data[ptr:ptr+ctId1Len], ctId1Data)
	ptr += ctId1Len
	copy(data[ptr:ptr+ctId2Len], ctId2Data)
	ptr += ctId2Len

	return
}

func (query *MultiplyQuery) UnmarshalBinary(data []byte) (err error) {
	ptr := 0 // Used to index data

	// Read lengths
	ctId1Len := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8
	ctId2Len := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8

	// Read fields
	if ctId1Len > 0 {
		var id uuid.UUID
		id, err = unmarshUUID(data[ptr : ptr+ctId1Len])
		query.CipherID1 = (CipherID)(id)
		ptr += ctId1Len
		if err != nil {
			return
		}
	} // TODO: else?
	if ctId2Len > 0 {
		var id uuid.UUID
		id, err = unmarshUUID(data[ptr : ptr+ctId2Len])
		query.CipherID2 = (CipherID)(id)
		ptr += ctId2Len
		if err != nil {
			return
		}
	} // TODO: else?

	return
}

func (req *MultiplyRequest) MarshalBinary() (data []byte, err error) {
	// Marshal RequestID
	idData, err := marshUUID((uuid.UUID)(req.MultiplyRequestID))
	if err != nil {
		return
	}
	idLen := len(idData)

	// Marshal MultiplyQuery
	queryData := make([]byte, 0)
	if req.MultiplyQuery != nil {
		queryData, err = req.MultiplyQuery.MarshalBinary()
		if err != nil {
			return
		}
	}
	queryLen := len(queryData)

	// Build data as [<idLen>, <queryLen>, <RequestID>, <MultiplyQuery>]
	data = make([]byte, 8+8+idLen+queryLen)
	ptr := 0 // Used to index data
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(idLen))
	ptr += 8
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(queryLen))
	ptr += 8
	copy(data[ptr:ptr+idLen], idData)
	ptr += idLen
	copy(data[ptr:ptr+queryLen], queryData)
	ptr += queryLen

	return
}

func (req *MultiplyRequest) UnmarshalBinary(data []byte) (err error) {
	ptr := 0 // Used to index data

	// Read lengths
	idLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8
	queryLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8

	// Read fields
	if idLen > 0 {
		var id uuid.UUID
		id, err = unmarshUUID(data[ptr : ptr+idLen])
		req.MultiplyRequestID = (MultiplyRequestID)(id)
		ptr += idLen
		if err != nil {
			return
		}
	} // TODO: else?
	if queryLen > 0 {
		err = req.MultiplyQuery.UnmarshalBinary(data[ptr : ptr+queryLen])
		ptr += queryLen
		if err != nil {
			return
		}
	} // TODO: else?

	return
}

func (reply *MultiplyReply) MarshalBinary() (data []byte, err error) {
	// Marshal RequestID
	idData, err := marshUUID((uuid.UUID)(reply.MultiplyRequestID))
	if err != nil {
		return
	}
	idLen := len(idData)

	// Transform the rest to a Response, then marshal it
	resp := &MultiplyResponse{reply.newCipherID, reply.valid}
	respData, err := resp.MarshalBinary()
	if err != nil {
		return
	}
	respLen := len(respData)

	// Build data as [<idLen>, <respLen>, <RequestID>, <MultiplyResponse>]
	data = make([]byte, 8+8+idLen+respLen)
	ptr := 0 // Used to index data
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(idLen))
	ptr += 8
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(respLen))
	ptr += 8
	copy(data[ptr:ptr+idLen], idData)
	ptr += idLen
	copy(data[ptr:ptr+respLen], respData)
	ptr += respLen

	return
}

func (reply *MultiplyReply) UnmarshalBinary(data []byte) (err error) {
	ptr := 0 // Used to index data

	// Read lengths
	idLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8
	respLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8

	// Read fields
	if idLen > 0 {
		var id uuid.UUID
		id, err = unmarshUUID(data[ptr : ptr+idLen])
		reply.MultiplyRequestID = (MultiplyRequestID)(id)
		ptr += idLen
		if err != nil {
			return
		}
	} // TODO: else?
	if respLen > 0 {
		resp := &MultiplyResponse{}
		err = resp.UnmarshalBinary(data[ptr : ptr+respLen])
		ptr += respLen
		if err != nil {
			return
		}

		reply.newCipherID = resp.NewCipherID
		reply.valid = resp.Valid
	} // TODO: else?

	return
}

func (resp *MultiplyResponse) MarshalBinary() (data []byte, err error) {
	// Marshal CipherID
	ctIdData, err := marshUUID((uuid.UUID)(resp.NewCipherID))
	if err != nil {
		return
	}
	ctIdLen := len(ctIdData)

	// Build data as [<ctIdLen>, <NewCipherID>, <Valid>]
	data = make([]byte, 8+ctIdLen+1)
	ptr := 0 // Used to index data
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(ctIdLen))
	ptr += 8
	copy(data[ptr:ptr+ctIdLen], ctIdData)
	ptr += ctIdLen
	data[ptr] = marshBool(resp.Valid)
	ptr += 1

	return
}

func (resp *MultiplyResponse) UnmarshalBinary(data []byte) (err error) {
	ptr := 0 // Used to index data

	// Read length
	ctIdLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8

	// Read fields
	if ctIdLen > 0 {
		var id uuid.UUID
		id, err = unmarshUUID(data[ptr : ptr+ctIdLen])
		resp.NewCipherID = (CipherID)(id)
		ptr += ctIdLen
		if err != nil {
			return
		}
	} // TODO: else?
	resp.Valid = unmarshBool(data[ptr])
	ptr += 1

	return
}

// Relinearise

func (query *RelinQuery) MarshalBinary() (data []byte, err error) {
	// Marshal CipherID
	ctIdData, err := marshUUID((uuid.UUID)(query.CipherID))
	if err != nil {
		return
	}
	ctIdLen := len(ctIdData)

	// Build data as [<ctIdLen>, <CipherID1>]
	data = make([]byte, 8+ctIdLen)
	ptr := 0 // Used to index data
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(ctIdLen))
	ptr += 8
	copy(data[ptr:ptr+ctIdLen], ctIdData)
	ptr += ctIdLen

	return
}

func (query *RelinQuery) UnmarshalBinary(data []byte) (err error) {
	ptr := 0 // Used to index data

	// Read lengths
	ctIdLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8

	// Read fields
	if ctIdLen > 0 {
		var id uuid.UUID
		id, err = unmarshUUID(data[ptr : ptr+ctIdLen])
		query.CipherID = (CipherID)(id)
		ptr += ctIdLen
		if err != nil {
			return
		}
	} // TODO: else?

	return
}

func (req *RelinRequest) MarshalBinary() (data []byte, err error) {
	// Marshal RequestID
	idData, err := marshUUID((uuid.UUID)(req.RelinRequestID))
	if err != nil {
		return
	}
	idLen := len(idData)

	// Marshal RelinQuery
	queryData := make([]byte, 0)
	if req.RelinQuery != nil {
		queryData, err = req.RelinQuery.MarshalBinary()
		if err != nil {
			return
		}
	}
	queryLen := len(queryData)

	// Build data as [<idLen>, <queryLen>, <RequestID>, <RelinQuery>]
	data = make([]byte, 8+8+idLen+queryLen)
	ptr := 0 // Used to index data
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(idLen))
	ptr += 8
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(queryLen))
	ptr += 8
	copy(data[ptr:ptr+idLen], idData)
	ptr += idLen
	copy(data[ptr:ptr+queryLen], queryData)
	ptr += queryLen

	return
}

func (req *RelinRequest) UnmarshalBinary(data []byte) (err error) {
	ptr := 0 // Used to index data

	// Read lengths
	idLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8
	queryLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8

	// Read fields
	if idLen > 0 {
		var id uuid.UUID
		id, err = unmarshUUID(data[ptr : ptr+idLen])
		req.RelinRequestID = (RelinRequestID)(id)
		ptr += idLen
		if err != nil {
			return
		}
	} // TODO: else?
	if queryLen > 0 {
		err = req.RelinQuery.UnmarshalBinary(data[ptr : ptr+queryLen])
		ptr += queryLen
		if err != nil {
			return
		}
	} // TODO: else?

	return
}

func (reply *RelinReply) MarshalBinary() (data []byte, err error) {
	// Marshal RequestID
	idData, err := marshUUID((uuid.UUID)(reply.RelinRequestID))
	if err != nil {
		return
	}
	idLen := len(idData)

	// Transform the rest to a Response, then marshal it
	resp := &RelinResponse{reply.valid}
	respData, err := resp.MarshalBinary()
	if err != nil {
		return
	}
	respLen := len(respData)

	// Build data as [<idLen>, <respLen>, <RequestID>, <RelinResponse>]
	data = make([]byte, 8+8+idLen+respLen)
	ptr := 0 // Used to index data
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(idLen))
	ptr += 8
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(respLen))
	ptr += 8
	copy(data[ptr:ptr+idLen], idData)
	ptr += idLen
	copy(data[ptr:ptr+respLen], respData)
	ptr += respLen

	return
}

func (reply *RelinReply) UnmarshalBinary(data []byte) (err error) {
	ptr := 0 // Used to index data

	// Read lengths
	idLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8
	respLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8

	// Read fields
	if idLen > 0 {
		var id uuid.UUID
		id, err = unmarshUUID(data[ptr : ptr+idLen])
		reply.RelinRequestID = (RelinRequestID)(id)
		ptr += idLen
		if err != nil {
			return
		}
	} // TODO: else?
	if respLen > 0 {
		resp := &RelinResponse{}
		err = resp.UnmarshalBinary(data[ptr : ptr+respLen])
		ptr += respLen
		if err != nil {
			return
		}

		reply.valid = resp.Valid
	} // TODO: else?

	return
}

func (resp *RelinResponse) MarshalBinary() (data []byte, err error) {
	// Build data as [<Valid>]
	data = make([]byte, 1)
	ptr := 0 // Used to index data
	data[ptr] = marshBool(resp.Valid)
	ptr += 1

	return
}

func (resp *RelinResponse) UnmarshalBinary(data []byte) (err error) {
	ptr := 0 // Used to index data

	// Read field
	resp.Valid = unmarshBool(data[ptr])
	ptr += 1

	return
}

// Refresh

func (query *RefreshQuery) MarshalBinary() (data []byte, err error) {
	// Marshal CipherID
	ctIdData, err := marshUUID((uuid.UUID)(query.CipherID))
	if err != nil {
		return
	}
	ctIdLen := len(ctIdData)

	// Build data as [<ctIdLen>, <CipherID1>]
	data = make([]byte, 8+ctIdLen)
	ptr := 0 // Used to index data
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(ctIdLen))
	ptr += 8
	copy(data[ptr:ptr+ctIdLen], ctIdData)
	ptr += ctIdLen

	return
}

func (query *RefreshQuery) UnmarshalBinary(data []byte) (err error) {
	ptr := 0 // Used to index data

	// Read lengths
	ctIdLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8

	// Read fields
	if ctIdLen > 0 {
		var id uuid.UUID
		id, err = unmarshUUID(data[ptr : ptr+ctIdLen])
		query.CipherID = (CipherID)(id)
		ptr += ctIdLen
		if err != nil {
			return
		}
	} // TODO: else?

	return
}

func (req *RefreshRequest) MarshalBinary() (data []byte, err error) {
	// Marshal RequestID
	idData, err := marshUUID((uuid.UUID)(req.RefreshRequestID))
	if err != nil {
		return
	}
	idLen := len(idData)

	// Marshal RefreshQuery
	queryData := make([]byte, 0)
	if req.RefreshQuery != nil {
		queryData, err = req.RefreshQuery.MarshalBinary()
		if err != nil {
			return
		}
	}
	queryLen := len(queryData)

	// Build data as [<idLen>, <queryLen>, <RequestID>, <RefreshQuery>]
	data = make([]byte, 8+8+idLen+queryLen)
	ptr := 0 // Used to index data
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(idLen))
	ptr += 8
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(queryLen))
	ptr += 8
	copy(data[ptr:ptr+idLen], idData)
	ptr += idLen
	copy(data[ptr:ptr+queryLen], queryData)
	ptr += queryLen

	return
}

func (req *RefreshRequest) UnmarshalBinary(data []byte) (err error) {
	ptr := 0 // Used to index data

	// Read lengths
	idLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8
	queryLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8

	// Read fields
	if idLen > 0 {
		var id uuid.UUID
		id, err = unmarshUUID(data[ptr : ptr+idLen])
		req.RefreshRequestID = (RefreshRequestID)(id)
		ptr += idLen
		if err != nil {
			return
		}
	} // TODO: else?
	if queryLen > 0 {
		err = req.RefreshQuery.UnmarshalBinary(data[ptr : ptr+queryLen])
		ptr += queryLen
		if err != nil {
			return
		}
	} // TODO: else?

	return
}

func (prep *RefreshBroadcast) MarshalBinary() (data []byte, err error) {
	// Marshal RequestID
	idData, err := marshUUID((uuid.UUID)(prep.RefreshRequestID))
	if err != nil {
		return
	}
	idLen := len(idData)

	// Marshal Ciphertext
	ctData := make([]byte, 0)
	if prep.ct != nil {
		ctData, err = prep.ct.MarshalBinary()
		if err != nil {
			return
		}
	}
	ctLen := len(ctData)

	// Build data as [<idLen>, <ctLen>, <RequestID>, <Ciphertext>]
	data = make([]byte, 8+8+idLen+ctLen)
	ptr := 0 // Used to index data
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(idLen))
	ptr += 8
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(ctLen))
	ptr += 8
	copy(data[ptr:ptr+idLen], idData)
	ptr += idLen
	copy(data[ptr:ptr+ctLen], ctData)
	ptr += ctLen

	return
}

func (prep *RefreshBroadcast) UnmarshalBinary(data []byte) (err error) {
	ptr := 0 // Used to index data

	// Read lengths
	idLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8
	ctLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8

	// Read fields
	if idLen > 0 {
		var id uuid.UUID
		id, err = unmarshUUID(data[ptr : ptr+idLen])
		prep.RefreshRequestID = (RefreshRequestID)(id)
		ptr += idLen
		if err != nil {
			return
		}
	} // TODO: else?
	if ctLen > 0 {
		err = prep.ct.UnmarshalBinary(data[ptr : ptr+ctLen])
		ptr += ctLen
		if err != nil {
			return
		}
	} // TODO: else?

	return
}

func (reply *RefreshReply) MarshalBinary() (data []byte, err error) {
	// Marshal RequestID
	idData, err := marshUUID((uuid.UUID)(reply.RefreshRequestID))
	if err != nil {
		return
	}
	idLen := len(idData)

	// Transform the rest to a Response, then marshal it
	resp := &RefreshResponse{reply.valid}
	respData, err := resp.MarshalBinary()
	if err != nil {
		return
	}
	respLen := len(respData)

	// Build data as [<idLen>, <respLen>, <RequestID>, <RefreshResponse>]
	data = make([]byte, 8+8+idLen+respLen)
	ptr := 0 // Used to index data
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(idLen))
	ptr += 8
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(respLen))
	ptr += 8
	copy(data[ptr:ptr+idLen], idData)
	ptr += idLen
	copy(data[ptr:ptr+respLen], respData)
	ptr += respLen

	return
}

func (reply *RefreshReply) UnmarshalBinary(data []byte) (err error) {
	ptr := 0 // Used to index data

	// Read lengths
	idLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8
	respLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8

	// Read fields
	if idLen > 0 {
		var id uuid.UUID
		id, err = unmarshUUID(data[ptr : ptr+idLen])
		reply.RefreshRequestID = (RefreshRequestID)(id)
		ptr += idLen
		if err != nil {
			return
		}
	} // TODO: else?
	if respLen > 0 {
		resp := &RefreshResponse{}
		err = resp.UnmarshalBinary(data[ptr : ptr+respLen])
		ptr += respLen
		if err != nil {
			return
		}

		reply.valid = resp.Valid
	} // TODO: else?

	return
}

func (resp *RefreshResponse) MarshalBinary() (data []byte, err error) {
	// Build data as [<Valid>]
	data = make([]byte, 1)
	ptr := 0 // Used to index data
	data[ptr] = marshBool(resp.Valid)
	ptr += 1

	return
}

func (resp *RefreshResponse) UnmarshalBinary(data []byte) (err error) {
	ptr := 0 // Used to index data

	// Read field
	resp.Valid = unmarshBool(data[ptr])
	ptr += 1

	return
}

// Rotation

func (query *RotationQuery) MarshalBinary() (data []byte, err error) {
	// Marshal CipherID
	ctIdData, err := marshUUID((uuid.UUID)(query.CipherID))
	if err != nil {
		return
	}
	ctIdLen := len(ctIdData)

	// Build data as [<ctIdLen>, <CipherID>, <K>, <RotIdx>]
	data = make([]byte, 8+ctIdLen+8+1) // RotIdx can be written on a byte
	ptr := 0                           // Used to index data
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(ctIdLen))
	ptr += 8
	copy(data[ptr:ptr+ctIdLen], ctIdData)
	ptr += ctIdLen
	binary.BigEndian.PutUint64(data[ptr:ptr+8], query.K)
	ptr += 8
	data[ptr] = byte(query.RotIdx)
	ptr += 1

	return
}

func (query *RotationQuery) UnmarshalBinary(data []byte) (err error) {
	ptr := 0 // Used to index data

	// Read length
	ctIdLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8

	// Read fields
	if ctIdLen > 0 {
		var id uuid.UUID
		id, err = unmarshUUID(data[ptr : ptr+ctIdLen])
		query.CipherID = (CipherID)(id)
		ptr += ctIdLen
		if err != nil {
			return
		}
	} // TODO: else?
	query.K = binary.BigEndian.Uint64(data[ptr : ptr+8])
	ptr += 8
	query.RotIdx = int(data[ptr])
	ptr += 1

	return
}

func (req *RotationRequest) MarshalBinary() (data []byte, err error) {
	// Marshal RequestID
	idData, err := marshUUID((uuid.UUID)(req.RotationRequestID))
	if err != nil {
		return
	}
	idLen := len(idData)

	// Marshal MultiplyQuery
	queryData := make([]byte, 0)
	if req.RotationQuery != nil {
		queryData, err = req.RotationQuery.MarshalBinary()
		if err != nil {
			return
		}
	}
	queryLen := len(queryData)

	// Build data as [<idLen>, <queryLen>, <RequestID>, <RotationQuery>]
	data = make([]byte, 8+8+idLen+queryLen)
	ptr := 0 // Used to index data
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(idLen))
	ptr += 8
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(queryLen))
	ptr += 8
	copy(data[ptr:ptr+idLen], idData)
	ptr += idLen
	copy(data[ptr:ptr+queryLen], queryData)
	ptr += queryLen

	return
}

func (req *RotationRequest) UnmarshalBinary(data []byte) (err error) {
	ptr := 0 // Used to index data

	// Read lengths
	idLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8
	queryLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8

	// Read fields
	if idLen > 0 {
		var id uuid.UUID
		id, err = unmarshUUID(data[ptr : ptr+idLen])
		req.RotationRequestID = (RotationRequestID)(id)
		ptr += idLen
		if err != nil {
			return
		}
	} // TODO: else?
	if queryLen > 0 {
		err = req.RotationQuery.UnmarshalBinary(data[ptr : ptr+queryLen])
		ptr += queryLen
		if err != nil {
			return
		}
	} // TODO: else?

	return
}

func (reply *RotationReply) MarshalBinary() (data []byte, err error) {
	// Marshal RequestID
	idData, err := marshUUID((uuid.UUID)(reply.RotationRequestID))
	if err != nil {
		return
	}
	idLen := len(idData)

	// Transform the rest to a Response, then marshal it
	resp := &RotationResponse{reply.Old, reply.New, reply.valid}
	respData, err := resp.MarshalBinary()
	if err != nil {
		return
	}
	respLen := len(respData)

	// Build data as [<idLen>, <respLen>, <RequestID>, <RotationResponse>]
	data = make([]byte, 8+8+idLen+respLen)
	ptr := 0 // Used to index data
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(idLen))
	ptr += 8
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(respLen))
	ptr += 8
	copy(data[ptr:ptr+idLen], idData)
	ptr += idLen
	copy(data[ptr:ptr+respLen], respData)
	ptr += respLen

	return
}

func (reply *RotationReply) UnmarshalBinary(data []byte) (err error) {
	ptr := 0 // Used to index data

	// Read lengths
	idLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8
	respLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8

	// Read fields
	if idLen > 0 {
		var id uuid.UUID
		id, err = unmarshUUID(data[ptr : ptr+idLen])
		reply.RotationRequestID = (RotationRequestID)(id)
		ptr += idLen
		if err != nil {
			return
		}
	} // TODO: else?
	if respLen > 0 {
		resp := &RotationResponse{}
		err = resp.UnmarshalBinary(data[ptr : ptr+respLen])
		ptr += respLen
		if err != nil {
			return
		}

		reply.Old = resp.Old
		reply.New = resp.New
		reply.valid = resp.Valid
	} // TODO: else?

	return
}

func (resp *RotationResponse) MarshalBinary() (data []byte, err error) {
	// Marshal Old
	oldIdData, err := marshUUID((uuid.UUID)(resp.Old))
	if err != nil {
		return
	}
	oldIdLen := len(oldIdData)

	// Marshal New
	newIdData, err := marshUUID((uuid.UUID)(resp.New))
	if err != nil {
		return
	}
	newIdLen := len(newIdData)

	// Build data as [<oldIdLen>, <newIdLen>, <Old>, <New>, <Valid>]
	data = make([]byte, 8+8+oldIdLen+newIdLen+1)
	ptr := 0 // Used to index data
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(oldIdLen))
	ptr += 8
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(newIdLen))
	ptr += 8
	copy(data[ptr:ptr+oldIdLen], oldIdData)
	ptr += oldIdLen
	copy(data[ptr:ptr+newIdLen], newIdData)
	ptr += newIdLen
	data[ptr] = marshBool(resp.Valid)
	ptr += 1

	return
}

func (resp *RotationResponse) UnmarshalBinary(data []byte) (err error) {
	ptr := 0 // Used to index data

	// Read lengths
	oldIdLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8
	newIdLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8

	// Read fields
	if oldIdLen > 0 {
		var id uuid.UUID
		id, err = unmarshUUID(data[ptr : ptr+oldIdLen])
		resp.Old = (CipherID)(id)
		ptr += oldIdLen
		if err != nil {
			return
		}
	} // TODO: else?
	if newIdLen > 0 {
		var id uuid.UUID
		id, err = unmarshUUID(data[ptr : ptr+newIdLen])
		resp.New = (CipherID)(id)
		ptr += newIdLen
		if err != nil {
			return
		}
	} // TODO: else?
	resp.Valid = unmarshBool(data[ptr])
	ptr += 1

	return
}

// Encryption to shares

func (query *EncToSharesQuery) MarshalBinary() (data []byte, err error) {
	// Marshal CipherID
	ctIdData, err := marshUUID((uuid.UUID)(query.CipherID))
	if err != nil {
		return
	}
	ctIdLen := len(ctIdData)

	// Build data as [<ctIdLen>, <CipherID1>]
	data = make([]byte, 8+ctIdLen)
	ptr := 0 // Used to index data
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(ctIdLen))
	ptr += 8
	copy(data[ptr:ptr+ctIdLen], ctIdData)
	ptr += ctIdLen

	return
}

func (query *EncToSharesQuery) UnmarshalBinary(data []byte) (err error) {
	ptr := 0 // Used to index data

	// Read lengths
	ctIdLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8

	// Read fields
	if ctIdLen > 0 {
		var id uuid.UUID
		id, err = unmarshUUID(data[ptr : ptr+ctIdLen])
		query.CipherID = (CipherID)(id)
		ptr += ctIdLen
		if err != nil {
			return
		}
	} // TODO: else?

	return
}

func (req *EncToSharesRequest) MarshalBinary() (data []byte, err error) {
	// Marshal RequestID
	idData, err := marshUUID((uuid.UUID)(req.EncToSharesRequestID))
	if err != nil {
		return
	}
	idLen := len(idData)

	// Marshal EncToSharesQuery
	queryData := make([]byte, 0)
	if req.EncToSharesQuery != nil {
		queryData, err = req.EncToSharesQuery.MarshalBinary()
		if err != nil {
			return
		}
	}
	queryLen := len(queryData)

	// Build data as [<idLen>, <queryLen>, <RequestID>, <EncToSharesQuery>]
	data = make([]byte, 8+8+idLen+queryLen)
	ptr := 0 // Used to index data
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(idLen))
	ptr += 8
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(queryLen))
	ptr += 8
	copy(data[ptr:ptr+idLen], idData)
	ptr += idLen
	copy(data[ptr:ptr+queryLen], queryData)
	ptr += queryLen

	return
}

func (req *EncToSharesRequest) UnmarshalBinary(data []byte) (err error) {
	ptr := 0 // Used to index data

	// Read lengths
	idLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8
	queryLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8

	// Read fields
	if idLen > 0 {
		var id uuid.UUID
		id, err = unmarshUUID(data[ptr : ptr+idLen])
		req.EncToSharesRequestID = (EncToSharesRequestID)(id)
		ptr += idLen
		if err != nil {
			return
		}
	} // TODO: else?
	if queryLen > 0 {
		err = req.EncToSharesQuery.UnmarshalBinary(data[ptr : ptr+queryLen])
		ptr += queryLen
		if err != nil {
			return
		}
	} // TODO: else?

	return
}

func (params *E2SParameters) MarshalBinary() (data []byte, err error) {
	// Marshal CipherID
	ctIdData, err := marshUUID((uuid.UUID)(params.cipherID))
	if err != nil {
		return
	}
	ctIdLen := len(ctIdData)

	// Marshal Ciphertext
	ctData := make([]byte, 0)
	if params.ct != nil {
		ctData, err = params.ct.MarshalBinary()
		if err != nil {
			return
		}
	}
	ctLen := len(ctData)

	// Build data as [<ctIdLen>, <ctLen>, <CipherID>, <Ciphertext>]
	data = make([]byte, 8+8+ctIdLen+ctLen)
	ptr := 0 // Used to index data
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(ctIdLen))
	ptr += 8
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(ctLen))
	ptr += 8
	copy(data[ptr:ptr+ctIdLen], ctIdData)
	ptr += ctIdLen
	copy(data[ptr:ptr+ctLen], ctData)
	ptr += ctLen

	return
}

func (params *E2SParameters) UnmarshalBinary(data []byte) (err error) {
	ptr := 0 // Used to index data

	// Read lengths
	ctIdLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8
	ctLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8

	// Read fields
	if ctIdLen > 0 {
		var id uuid.UUID
		id, err = unmarshUUID(data[ptr : ptr+ctIdLen])
		params.cipherID = (CipherID)(id)
		ptr += ctIdLen
		if err != nil {
			return
		}
	} // TODO: else?
	if ctLen > 0 {
		err = params.ct.UnmarshalBinary(data[ptr : ptr+ctLen])
		ptr += ctLen
		if err != nil {
			return
		}
	} // TODO: else?

	return
}

func (prep *EncToSharesBroadcast) MarshalBinary() (data []byte, err error) {
	// Marshal RequestID
	idData, err := marshUUID((uuid.UUID)(prep.EncToSharesRequestID))
	if err != nil {
		return
	}
	idLen := len(idData)

	// Marshal E2SParameters
	paramsData := make([]byte, 0)
	if prep.params != nil {
		paramsData, err = prep.params.MarshalBinary()
		if err != nil {
			return
		}
	}
	paramsLen := len(paramsData)

	// Build data as [<idLen>, <paramsLen>, <RequestID>, <E2SParameters>]
	data = make([]byte, 8+8+idLen+paramsLen)
	ptr := 0 // Used to index data
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(idLen))
	ptr += 8
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(paramsLen))
	ptr += 8
	copy(data[ptr:ptr+idLen], idData)
	ptr += idLen
	copy(data[ptr:ptr+paramsLen], paramsData)
	ptr += paramsLen

	return
}

func (prep *EncToSharesBroadcast) UnmarshalBinary(data []byte) (err error) {
	ptr := 0 // Used to index data

	// Read lengths
	idLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8
	paramsLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8

	// Read fields
	if idLen > 0 {
		var id uuid.UUID
		id, err = unmarshUUID(data[ptr : ptr+idLen])
		prep.EncToSharesRequestID = (EncToSharesRequestID)(id)
		ptr += idLen
		if err != nil {
			return
		}
	} // TODO: else?
	if paramsLen > 0 {
		err = prep.params.UnmarshalBinary(data[ptr : ptr+paramsLen])
		ptr += paramsLen
		if err != nil {
			return
		}
	} // TODO: else?

	return
}

func (reply *EncToSharesReply) MarshalBinary() (data []byte, err error) {
	// Marshal RequestID
	idData, err := marshUUID((uuid.UUID)(reply.EncToSharesRequestID))
	if err != nil {
		return
	}
	idLen := len(idData)

	// Transform the rest to a Response, then marshal it
	resp := &EncToSharesResponse{reply.valid}
	respData, err := resp.MarshalBinary()
	if err != nil {
		return
	}
	respLen := len(respData)

	// Build data as [<idLen>, <respLen>, <RequestID>, <EncToSharesResponse>]
	data = make([]byte, 8+8+idLen+respLen)
	ptr := 0 // Used to index data
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(idLen))
	ptr += 8
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(respLen))
	ptr += 8
	copy(data[ptr:ptr+idLen], idData)
	ptr += idLen
	copy(data[ptr:ptr+respLen], respData)
	ptr += respLen

	return
}

func (reply *EncToSharesReply) UnmarshalBinary(data []byte) (err error) {
	ptr := 0 // Used to index data

	// Read lengths
	idLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8
	respLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8

	// Read fields
	if idLen > 0 {
		var id uuid.UUID
		id, err = unmarshUUID(data[ptr : ptr+idLen])
		reply.EncToSharesRequestID = (EncToSharesRequestID)(id)
		ptr += idLen
		if err != nil {
			return
		}
	} // TODO: else?
	if respLen > 0 {
		resp := &EncToSharesResponse{}
		err = resp.UnmarshalBinary(data[ptr : ptr+respLen])
		ptr += respLen
		if err != nil {
			return
		}

		reply.valid = resp.Valid
	} // TODO: else?

	return
}

func (resp *EncToSharesResponse) MarshalBinary() (data []byte, err error) {
	// Build data as [<Valid>]
	data = make([]byte, 1)
	ptr := 0 // Used to index data
	data[ptr] = marshBool(resp.Valid)
	ptr += 1

	return
}

func (resp *EncToSharesResponse) UnmarshalBinary(data []byte) (err error) {
	ptr := 0 // Used to index data

	// Read field
	resp.Valid = unmarshBool(data[ptr])
	ptr += 1

	return
}

// Shares to encryption

func (query *SharesToEncQuery) MarshalBinary() (data []byte, err error) {
	// Marshal CipherID
	ctIdData, err := marshUUID((uuid.UUID)(query.CipherID))
	if err != nil {
		return
	}
	ctIdLen := len(ctIdData)

	// Build data as [<ctIdLen>, <CipherID1>]
	data = make([]byte, 8+ctIdLen)
	ptr := 0 // Used to index data
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(ctIdLen))
	ptr += 8
	copy(data[ptr:ptr+ctIdLen], ctIdData)
	ptr += ctIdLen

	return
}

func (query *SharesToEncQuery) UnmarshalBinary(data []byte) (err error) {
	ptr := 0 // Used to index data

	// Read lengths
	ctIdLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8

	// Read fields
	if ctIdLen > 0 {
		var id uuid.UUID
		id, err = unmarshUUID(data[ptr : ptr+ctIdLen])
		query.CipherID = (CipherID)(id)
		ptr += ctIdLen
		if err != nil {
			return
		}
	} // TODO: else?

	return
}

func (req *SharesToEncRequest) MarshalBinary() (data []byte, err error) {
	// Marshal RequestID
	idData, err := marshUUID((uuid.UUID)(req.SharesToEncRequestID))
	if err != nil {
		return
	}
	idLen := len(idData)

	// Marshal SharesToEncQuery
	queryData := make([]byte, 0)
	if req.SharesToEncQuery != nil {
		queryData, err = req.SharesToEncQuery.MarshalBinary()
		if err != nil {
			return
		}
	}
	queryLen := len(queryData)

	// Build data as [<idLen>, <queryLen>, <RequestID>, <SharesToEncQuery>]
	data = make([]byte, 8+8+idLen+queryLen)
	ptr := 0 // Used to index data
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(idLen))
	ptr += 8
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(queryLen))
	ptr += 8
	copy(data[ptr:ptr+idLen], idData)
	ptr += idLen
	copy(data[ptr:ptr+queryLen], queryData)
	ptr += queryLen

	return
}

func (req *SharesToEncRequest) UnmarshalBinary(data []byte) (err error) {
	ptr := 0 // Used to index data

	// Read lengths
	idLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8
	queryLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8

	// Read fields
	if idLen > 0 {
		var id uuid.UUID
		id, err = unmarshUUID(data[ptr : ptr+idLen])
		req.SharesToEncRequestID = (SharesToEncRequestID)(id)
		ptr += idLen
		if err != nil {
			return
		}
	} // TODO: else?
	if queryLen > 0 {
		err = req.SharesToEncQuery.UnmarshalBinary(data[ptr : ptr+queryLen])
		ptr += queryLen
		if err != nil {
			return
		}
	} // TODO: else?

	return
}

func (params *S2EParameters) MarshalBinary() (data []byte, err error) {
	// Marshal CipherID
	ctIdData, err := marshUUID((uuid.UUID)(params.cipherID))
	if err != nil {
		return
	}
	ctIdLen := len(ctIdData)

	// Build data as [<ctIdLen>, <CipherID>]
	data = make([]byte, 8+ctIdLen)
	ptr := 0 // Used to index data
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(ctIdLen))
	ptr += 8
	copy(data[ptr:ptr+ctIdLen], ctIdData)
	ptr += ctIdLen

	return
}

func (params *S2EParameters) UnmarshalBinary(data []byte) (err error) {
	ptr := 0 // Used to index data

	// Read lengths
	ctIdLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8

	// Read fields
	if ctIdLen > 0 {
		var id uuid.UUID
		id, err = unmarshUUID(data[ptr : ptr+ctIdLen])
		params.cipherID = (CipherID)(id)
		ptr += ctIdLen
		if err != nil {
			return
		}
	} // TODO: else?

	return
}

func (prep *SharesToEncBroadcast) MarshalBinary() (data []byte, err error) {
	// Marshal RequestID
	idData, err := marshUUID((uuid.UUID)(prep.SharesToEncRequestID))
	if err != nil {
		return
	}
	idLen := len(idData)

	// Marshal S2EParameters
	paramsData := make([]byte, 0)
	if prep.params != nil {
		paramsData, err = prep.params.MarshalBinary()
		if err != nil {
			return
		}
	}
	paramsLen := len(paramsData)

	// Build data as [<idLen>, <paramsLen>, <RequestID>, <S2EParameters>]
	data = make([]byte, 8+8+idLen+paramsLen)
	ptr := 0 // Used to index data
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(idLen))
	ptr += 8
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(paramsLen))
	ptr += 8
	copy(data[ptr:ptr+idLen], idData)
	ptr += idLen
	copy(data[ptr:ptr+paramsLen], paramsData)
	ptr += paramsLen

	return
}

func (prep *SharesToEncBroadcast) UnmarshalBinary(data []byte) (err error) {
	ptr := 0 // Used to index data

	// Read lengths
	idLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8
	paramsLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8

	// Read fields
	if idLen > 0 {
		var id uuid.UUID
		id, err = unmarshUUID(data[ptr : ptr+idLen])
		prep.SharesToEncRequestID = (SharesToEncRequestID)(id)
		ptr += idLen
		if err != nil {
			return
		}
	} // TODO: else?
	if paramsLen > 0 {
		err = prep.params.UnmarshalBinary(data[ptr : ptr+paramsLen])
		ptr += paramsLen
		if err != nil {
			return
		}
	} // TODO: else?

	return
}

func (reply *SharesToEncReply) MarshalBinary() (data []byte, err error) {
	// Marshal RequestID
	idData, err := marshUUID((uuid.UUID)(reply.SharesToEncRequestID))
	if err != nil {
		return
	}
	idLen := len(idData)

	// Transform the rest to a Response, then marshal it
	resp := &SharesToEncResponse{reply.valid}
	respData, err := resp.MarshalBinary()
	if err != nil {
		return
	}
	respLen := len(respData)

	// Build data as [<idLen>, <respLen>, <RequestID>, <SharesToEncResponse>]
	data = make([]byte, 8+8+idLen+respLen)
	ptr := 0 // Used to index data
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(idLen))
	ptr += 8
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(respLen))
	ptr += 8
	copy(data[ptr:ptr+idLen], idData)
	ptr += idLen
	copy(data[ptr:ptr+respLen], respData)
	ptr += respLen

	return
}

func (reply *SharesToEncReply) UnmarshalBinary(data []byte) (err error) {
	ptr := 0 // Used to index data

	// Read lengths
	idLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8
	respLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8

	// Read fields
	if idLen > 0 {
		var id uuid.UUID
		id, err = unmarshUUID(data[ptr : ptr+idLen])
		reply.SharesToEncRequestID = (SharesToEncRequestID)(id)
		ptr += idLen
		if err != nil {
			return
		}
	} // TODO: else?
	if respLen > 0 {
		resp := &SharesToEncResponse{}
		err = resp.UnmarshalBinary(data[ptr : ptr+respLen])
		ptr += respLen
		if err != nil {
			return
		}

		reply.valid = resp.Valid
	} // TODO: else?

	return
}

func (resp *SharesToEncResponse) MarshalBinary() (data []byte, err error) {
	// Build data as [<Valid>]
	data = make([]byte, 1)
	ptr := 0 // Used to index data
	data[ptr] = marshBool(resp.Valid)
	ptr += 1

	return
}

func (resp *SharesToEncResponse) UnmarshalBinary(data []byte) (err error) {
	ptr := 0 // Used to index data

	// Read field
	resp.Valid = unmarshBool(data[ptr])
	ptr += 1

	return
}
*/
