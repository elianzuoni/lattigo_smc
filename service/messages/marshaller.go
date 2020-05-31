// BinaryMarshaller implementation of message structures that need it.

package messages

import (
	"encoding/binary"
	"github.com/ldsec/lattigo/bfv"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/protobuf"
	uuid "gopkg.in/satori/go.uuid.v1"
)

// Code snippets for marshallers and unmarshallers

/*

// Marshal

// Marshal ID
idData, err := id.MarshalBinary()
if err != nil {
	return
}
idLen := len(idData)

// Marshal field that can be nil
fieldData := make([]byte, 0)
if field != nil {
	fieldData, err = field.MarshalBinary()
	if err != nil {
		return
	}
}
fieldLen := len(fieldData)

// Build data as [<fieldLen>..., <field>...]
data = make([]byte, sum of 8's + sum of lengths of fields)
ptr := 0 	// Used to index data

// Add a uint64
binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64)
ptr += 8

// Add ID or field
copy(data[ptr:ptr+fieldLen], fieldData)
ptr += fieldLen

// Add an int
binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(int))
ptr += 8

// Add a bool
data[ptr] = marshBool(bool)
ptr += 1

// Unmarshal

ptr := 0 // Used to index data

// Read lengths
fieldLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
ptr += 8

// Read field or ID
if fieldLen > 0 {
	err = field.UnmarshalBinary(data[ptr : ptr+fieldLen])
	ptr += fieldLen
	if err != nil {
		return
	}
}

// Read bool
bool = unmarshBool(data[ptr])
ptr += 1

*/

func marshBool(b bool) byte {
	if b {
		return byte(1)
	}
	return byte(0)
}
func unmarshBool(b byte) bool {
	return b == byte(1)
}

// SessionID

func (id *SessionID) MarshalBinary() ([]byte, error) {
	return (*uuid.UUID)(id).MarshalBinary()
}
func (id *SessionID) UnmarshalBinary(data []byte) error {
	return (*uuid.UUID)(id).UnmarshalBinary(data)
}

// CircuitID

func (id *CircuitID) MarshalBinary() ([]byte, error) {
	return (*uuid.UUID)(id).MarshalBinary()
}
func (id *CircuitID) UnmarshalBinary(data []byte) error {
	return (*uuid.UUID)(id).UnmarshalBinary(data)
}

// CipherID

func (id *CipherID) MarshalBinary() (data []byte, err error) {
	// Marshal Owner
	ownData := []byte(id.Owner)
	ownLen := len(ownData)

	// Marshal ID
	idData, err := id.ID.MarshalBinary()
	if err != nil {
		return
	}
	idLen := len(idData)

	// Build data as [<ownLen>, <idLen>, <owner>, <ID>]
	data = make([]byte, 2*8+ownLen+idLen)
	ptr := 0 // Used to index data
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(ownLen))
	ptr += 8
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(idLen))
	ptr += 8
	copy(data[ptr:ptr+ownLen], ownData)
	ptr += ownLen
	copy(data[ptr:ptr+idLen], idData)
	ptr += idLen

	return
}
func (id *CipherID) UnmarshalBinary(data []byte) (err error) {
	ptr := 0 // Used to index data

	// Read lengths
	ownLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8
	idLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8

	// Read Owner
	if ownLen > 0 {
		id.Owner = string(data[ptr : ptr+ownLen])
		ptr += ownLen
	}

	// Read ID
	if idLen > 0 {
		err = id.ID.UnmarshalBinary(data[ptr : ptr+idLen])
		ptr += idLen
		if err != nil {
			return
		}
	}

	return
}

// SharesID

func (id *SharesID) MarshalBinary() (data []byte, err error) {
	return (*uuid.UUID)(id).MarshalBinary()
}
func (id *SharesID) UnmarshalBinary(data []byte) (err error) {
	return (*uuid.UUID)(id).UnmarshalBinary(data)
}

// Create Session

func (query *CreateSessionQuery) MarshalBinary() (data []byte, err error) {
	// Marshal Roster
	rosData, err := protobuf.Encode(query.Roster)
	if err != nil {
		return
	}
	rosLen := len(rosData)

	// Marshal Params
	parData, err := query.Params.MarshalBinary()
	if err != nil {
		return
	}
	parLen := len(parData)

	// Build data as [<rosLen>, <parLen>, <Roster>, <Params>]
	data = make([]byte, 2*8+rosLen+parLen)
	ptr := 0 // Used to index data
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(rosLen))
	ptr += 8
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(parLen))
	ptr += 8
	copy(data[ptr:ptr+rosLen], rosData)
	ptr += rosLen
	copy(data[ptr:ptr+parLen], parData)
	ptr += parLen

	return
}
func (query *CreateSessionQuery) UnmarshalBinary(data []byte) (err error) {
	ptr := 0 // Used to index data

	// Read lengths
	rosLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8
	parLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8

	// Read Roster
	if rosLen > 0 {
		if query.Roster == nil {
			query.Roster = &onet.Roster{}
		}
		err = protobuf.Decode(data[ptr:ptr+rosLen], query.Roster)
		ptr += rosLen
		if err != nil {
			return
		}
	}

	// Read CiphertextID
	if parLen > 0 {
		if query.Params == nil {
			query.Params = &bfv.Parameters{}
		}
		err = query.Params.UnmarshalBinary(data[ptr : ptr+parLen])
		ptr += parLen
		if err != nil {
			return
		}
	}

	return
}

func (cfg *CreateSessionConfig) MarshalBinary() (data []byte, err error) {
	// Marshal SessionID
	sidData, err := cfg.SessionID.MarshalBinary()
	if err != nil {
		return
	}
	sidLen := len(sidData)

	// Marshal Roster
	rosData, err := protobuf.Encode(cfg.Roster)
	if err != nil {
		return
	}
	rosLen := len(rosData)

	// Marshal Params
	parData, err := cfg.Params.MarshalBinary()
	if err != nil {
		return
	}
	parLen := len(parData)

	// Build data as [<sidLen>, <rosLen>, <parLen>, <SessionID>, <Roster>, <Params>]
	data = make([]byte, 3*8+sidLen+rosLen+parLen)
	ptr := 0 // Used to index data
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(sidLen))
	ptr += 8
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(rosLen))
	ptr += 8
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(parLen))
	ptr += 8
	copy(data[ptr:ptr+sidLen], sidData)
	ptr += sidLen
	copy(data[ptr:ptr+rosLen], rosData)
	ptr += rosLen
	copy(data[ptr:ptr+parLen], parData)
	ptr += parLen

	return
}
func (cfg *CreateSessionConfig) UnmarshalBinary(data []byte) (err error) {
	ptr := 0 // Used to index data

	// Read lengths
	sidLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8
	rosLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8
	parLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8

	// Read SessionID
	if sidLen > 0 {
		err = cfg.SessionID.UnmarshalBinary(data[ptr : ptr+sidLen])
		ptr += sidLen
		if err != nil {
			return
		}
	}

	// Read Roster
	if rosLen > 0 {
		if cfg.Roster == nil {
			cfg.Roster = &onet.Roster{}
		}
		err = protobuf.Decode(data[ptr:ptr+rosLen], cfg.Roster)
		ptr += rosLen
		if err != nil {
			return
		}
	}

	// Read CiphertextID
	if parLen > 0 {
		if cfg.Params == nil {
			cfg.Params = &bfv.Parameters{}
		}
		err = cfg.Params.UnmarshalBinary(data[ptr : ptr+parLen])
		ptr += parLen
		if err != nil {
			return
		}
	}

	return
}

func (resp *CreateSessionResponse) MarshalBinary() (data []byte, err error) {
	// Marshal SessionID
	sidData, err := resp.SessionID.MarshalBinary()
	if err != nil {
		return
	}
	sidLen := len(sidData)

	// Build data as [<sidLen>, <SessionID>, <Valid>]
	data = make([]byte, 8+sidLen+1)
	ptr := 0 // Used to index data
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(sidLen))
	ptr += 8
	copy(data[ptr:ptr+sidLen], sidData)
	ptr += sidLen
	data[ptr] = marshBool(resp.Valid)
	ptr += 1

	return
}
func (resp *CreateSessionResponse) UnmarshalBinary(data []byte) (err error) {
	ptr := 0 // Used to index data

	// Read length
	sidLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8

	// Read fields
	if sidLen > 0 {
		err = resp.SessionID.UnmarshalBinary(data[ptr : ptr+sidLen])
		ptr += sidLen
		if err != nil {
			return
		}
	}
	resp.Valid = unmarshBool(data[ptr])
	ptr += 1

	return
}

// Close Session

func (cfg *CloseSessionConfig) MarshalBinary() (data []byte, err error) {
	// Marshal SessionID
	sidData, err := cfg.SessionID.MarshalBinary()
	if err != nil {
		return
	}
	sidLen := len(sidData)

	// Build data as [<sidLen>, <SessionID>]
	data = make([]byte, 1*8+sidLen)
	ptr := 0 // Used to index data
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(sidLen))
	ptr += 8
	copy(data[ptr:ptr+sidLen], sidData)
	ptr += sidLen

	return
}
func (cfg *CloseSessionConfig) UnmarshalBinary(data []byte) (err error) {
	ptr := 0 // Used to index data

	// Read lengths
	sidLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8

	// Read SessionID
	if sidLen > 0 {
		err = cfg.SessionID.UnmarshalBinary(data[ptr : ptr+sidLen])
		ptr += sidLen
		if err != nil {
			return
		}
	}

	return
}

// Generate Public Key

func (cfg *GenPubKeyConfig) MarshalBinary() (data []byte, err error) {
	// Marshal SessionID
	sidData, err := cfg.SessionID.MarshalBinary()
	if err != nil {
		return
	}
	sidLen := len(sidData)

	// Marshal Seed
	seedLen := len(cfg.Seed)

	// Build data as [<sidLen>, <seedLen>, <SessionID>, <Seed>]
	data = make([]byte, 2*8+sidLen+seedLen)
	ptr := 0 // Used to index data
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(sidLen))
	ptr += 8
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(seedLen))
	ptr += 8
	copy(data[ptr:ptr+sidLen], sidData)
	ptr += sidLen
	copy(data[ptr:ptr+seedLen], cfg.Seed)
	ptr += seedLen

	return
}
func (cfg *GenPubKeyConfig) UnmarshalBinary(data []byte) (err error) {
	ptr := 0 // Used to index data

	// Read lengths
	sidLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8
	seedLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8

	// Read SessionID
	if sidLen > 0 {
		err = cfg.SessionID.UnmarshalBinary(data[ptr : ptr+sidLen])
		ptr += sidLen
		if err != nil {
			return
		}
	}
	// Read Seed
	cfg.Seed = make([]byte, seedLen)
	copy(cfg.Seed, data[ptr:ptr+seedLen])
	ptr += seedLen

	return
}

func (resp *GenPubKeyResponse) MarshalBinary() (data []byte, err error) {
	// Marshal Public Key
	pkData := make([]byte, 0)
	if resp.MasterPublicKey != nil {
		pkData, err = resp.MasterPublicKey.MarshalBinary()
		if err != nil {
			return
		}
	}
	pkLen := len(pkData)

	// Build data as [<pkLen>, <pk>, <valid>]
	data = make([]byte, 8+pkLen+1)
	ptr := 0 // Used to index data
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(pkLen))
	ptr += 8
	copy(data[ptr:ptr+pkLen], pkData)
	ptr += pkLen
	data[ptr] = marshBool(resp.Valid)
	ptr += 1

	return
}
func (resp *GenPubKeyResponse) UnmarshalBinary(data []byte) (err error) {
	ptr := 0 // Used to index data

	// Read lengths
	pkLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8

	// Read PublicKey
	if pkLen > 0 {
		if resp.MasterPublicKey == nil {
			resp.MasterPublicKey = &bfv.PublicKey{}
		}
		err = resp.MasterPublicKey.UnmarshalBinary(data[ptr : ptr+pkLen])
		ptr += pkLen
		if err != nil {
			return
		}
	}

	// Read Valid
	resp.Valid = unmarshBool(data[ptr])
	ptr += 1

	return
}

// Generate evaluation key

func (cfg *GenEvalKeyConfig) MarshalBinary() (data []byte, err error) {
	// Marshal SessionID
	sidData, err := cfg.SessionID.MarshalBinary()
	if err != nil {
		return
	}
	sidLen := len(sidData)

	// Marshal Seed
	seedLen := len(cfg.Seed)

	// Build data as [<sidLen>, <seedLen>, <SessionID>, <Seed>]
	data = make([]byte, 2*8+sidLen+seedLen)
	ptr := 0 // Used to index data
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(sidLen))
	ptr += 8
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(seedLen))
	ptr += 8
	copy(data[ptr:ptr+sidLen], sidData)
	ptr += sidLen
	copy(data[ptr:ptr+seedLen], cfg.Seed)
	ptr += seedLen

	return
}
func (cfg *GenEvalKeyConfig) UnmarshalBinary(data []byte) (err error) {
	ptr := 0 // Used to index data

	// Read lengths
	sidLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8
	seedLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8

	// Read SessionID
	if sidLen > 0 {
		err = cfg.SessionID.UnmarshalBinary(data[ptr : ptr+sidLen])
		ptr += sidLen
		if err != nil {
			return
		}
	}
	// Read Seed
	cfg.Seed = make([]byte, seedLen)
	copy(cfg.Seed, data[ptr:ptr+seedLen])
	ptr += seedLen

	return
}

func (cfg *GenRotKeyConfig) MarshalBinary() (data []byte, err error) {
	// Marshal SessionID
	sidData, err := cfg.SessionID.MarshalBinary()
	if err != nil {
		return
	}
	sidLen := len(sidData)

	// Marshal Seed
	seedLen := len(cfg.Seed)

	// Build data as [<sidLen>, <seedLen>, <SessionID>, <RotIdx>, <K>, <Seed>]
	data = make([]byte, 2*8+sidLen+8+8+seedLen)
	ptr := 0 // Used to index data
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(sidLen))
	ptr += 8
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(seedLen))
	ptr += 8
	copy(data[ptr:ptr+sidLen], sidData)
	ptr += sidLen
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(cfg.RotIdx))
	ptr += 8
	binary.BigEndian.PutUint64(data[ptr:ptr+8], cfg.K)
	ptr += 8
	copy(data[ptr:ptr+seedLen], cfg.Seed)
	ptr += seedLen

	return
}
func (cfg *GenRotKeyConfig) UnmarshalBinary(data []byte) (err error) {
	ptr := 0 // Used to index data

	// Read lengths
	sidLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8
	seedLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8

	// Read SessionID
	if sidLen > 0 {
		err = cfg.SessionID.UnmarshalBinary(data[ptr : ptr+sidLen])
		ptr += sidLen
		if err != nil {
			return
		}
	}
	// Read RotIdx
	cfg.RotIdx = int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8
	// Read K
	cfg.K = binary.BigEndian.Uint64(data[ptr : ptr+8])
	ptr += 8
	// Read Seed
	cfg.Seed = make([]byte, seedLen)
	copy(cfg.Seed, data[ptr:ptr+seedLen])
	ptr += seedLen

	return
}

// Get Public Key

func (id *GetPubKeyRequestID) MarshalBinary() ([]byte, error) {
	return (*uuid.UUID)(id).MarshalBinary()
}
func (id *GetPubKeyRequestID) UnmarshalBinary(data []byte) error {
	return (*uuid.UUID)(id).UnmarshalBinary(data)
}

func (rep *GetPubKeyReply) MarshalBinary() (data []byte, err error) {
	// Marshal RequestID
	ridData, err := rep.ReqID.MarshalBinary()
	if err != nil {
		return
	}
	ridLen := len(ridData)

	// Marshal Public Key
	pkData := make([]byte, 0)
	if rep.PublicKey != nil {
		pkData, err = rep.PublicKey.MarshalBinary()
		if err != nil {
			return
		}
	}
	pkLen := len(pkData)

	// Build data as [<ridLen>, <pkLen>, <ReqID>, <pk>, <valid>]
	data = make([]byte, 2*8+ridLen+pkLen+1)
	ptr := 0 // Used to index data
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(ridLen))
	ptr += 8
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(pkLen))
	ptr += 8
	copy(data[ptr:ptr+ridLen], ridData)
	ptr += ridLen
	copy(data[ptr:ptr+pkLen], pkData)
	ptr += pkLen
	data[ptr] = marshBool(rep.Valid)
	ptr += 1

	return
}
func (rep *GetPubKeyReply) UnmarshalBinary(data []byte) (err error) {
	ptr := 0 // Used to index data

	// Read lengths
	ridLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8
	pkLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8

	// Read RequestID
	if ridLen > 0 {
		err = rep.ReqID.UnmarshalBinary(data[ptr : ptr+ridLen])
		ptr += ridLen
		if err != nil {
			return
		}
	}

	// Read PublicKey
	if pkLen > 0 {
		if rep.PublicKey == nil {
			rep.PublicKey = &bfv.PublicKey{}
		}
		err = rep.PublicKey.UnmarshalBinary(data[ptr : ptr+pkLen])
		ptr += pkLen
		if err != nil {
			return
		}
	}

	// Read Valid
	rep.Valid = unmarshBool(data[ptr])
	ptr += 1

	return
}

// Get Evaluation Key

func (id *GetEvalKeyRequestID) MarshalBinary() ([]byte, error) {
	return (*uuid.UUID)(id).MarshalBinary()
}
func (id *GetEvalKeyRequestID) UnmarshalBinary(data []byte) error {
	return (*uuid.UUID)(id).UnmarshalBinary(data)
}

func (rep *GetEvalKeyReply) MarshalBinary() (data []byte, err error) {
	// Marshal RequestID
	ridData, err := rep.ReqID.MarshalBinary()
	if err != nil {
		return
	}
	ridLen := len(ridData)

	// Marshal Evaluation Key
	evkData := make([]byte, 0)
	if rep.EvaluationKey != nil {
		evkData, err = rep.EvaluationKey.MarshalBinary()
		if err != nil {
			return
		}
	}
	evkLen := len(evkData)

	// Build data as [<ridLen>, <evkLen>, <ReqID>, <evk>, <valid>]
	data = make([]byte, 2*8+ridLen+evkLen+1)
	ptr := 0 // Used to index data
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(ridLen))
	ptr += 8
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(evkLen))
	ptr += 8
	copy(data[ptr:ptr+ridLen], ridData)
	ptr += ridLen
	copy(data[ptr:ptr+evkLen], evkData)
	ptr += evkLen
	data[ptr] = marshBool(rep.Valid)
	ptr += 1

	return
}
func (rep *GetEvalKeyReply) UnmarshalBinary(data []byte) (err error) {
	ptr := 0 // Used to index data

	// Read lengths
	ridLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8
	evkLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8

	// Read RequestID
	if ridLen > 0 {
		err = rep.ReqID.UnmarshalBinary(data[ptr : ptr+ridLen])
		ptr += ridLen
		if err != nil {
			return
		}
	}

	// Read PublicKey
	if evkLen > 0 {
		if rep.EvaluationKey == nil {
			rep.EvaluationKey = &bfv.EvaluationKey{}
		}
		err = rep.EvaluationKey.UnmarshalBinary(data[ptr : ptr+evkLen])
		ptr += evkLen
		if err != nil {
			return
		}
	}

	// Read Valid
	rep.Valid = unmarshBool(data[ptr])
	ptr += 1

	return
}

// Get Rotation Key

func (id *GetRotKeyRequestID) MarshalBinary() ([]byte, error) {
	return (*uuid.UUID)(id).MarshalBinary()
}
func (id *GetRotKeyRequestID) UnmarshalBinary(data []byte) error {
	return (*uuid.UUID)(id).UnmarshalBinary(data)
}

func (rep *GetRotKeyReply) MarshalBinary() (data []byte, err error) {
	// Marshal RequestID
	ridData, err := rep.ReqID.MarshalBinary()
	if err != nil {
		return
	}
	ridLen := len(ridData)

	// Marshal Rotation Key
	rotkData := make([]byte, 0)
	if rep.RotationKey != nil {
		rotkData, err = rep.RotationKey.MarshalBinary()
		if err != nil {
			return
		}
	}
	rotkLen := len(rotkData)

	// Build data as [<ridLen>, <rotkLen>, <ReqID>, <rotk>, <valid>]
	data = make([]byte, 2*8+ridLen+rotkLen+1)
	ptr := 0 // Used to index data
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(ridLen))
	ptr += 8
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(rotkLen))
	ptr += 8
	copy(data[ptr:ptr+ridLen], ridData)
	ptr += ridLen
	copy(data[ptr:ptr+rotkLen], rotkData)
	ptr += rotkLen
	data[ptr] = marshBool(rep.Valid)
	ptr += 1

	return
}
func (rep *GetRotKeyReply) UnmarshalBinary(data []byte) (err error) {
	ptr := 0 // Used to index data

	// Read lengths
	ridLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8
	rotkLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8

	// Read RequestID
	if ridLen > 0 {
		err = rep.ReqID.UnmarshalBinary(data[ptr : ptr+ridLen])
		ptr += ridLen
		if err != nil {
			return
		}
	}

	// Read PublicKey
	if rotkLen > 0 {
		if rep.RotationKey == nil {
			rep.RotationKey = &bfv.RotationKeys{}
		}
		err = rep.RotationKey.UnmarshalBinary(data[ptr : ptr+rotkLen])
		ptr += rotkLen
		if err != nil {
			return
		}
	}

	// Read Valid
	rep.Valid = unmarshBool(data[ptr])
	ptr += 1

	return
}

// Store

func (query *StoreQuery) MarshalBinary() (data []byte, err error) {
	// Marshal SessionID
	sidData, err := query.SessionID.MarshalBinary()
	if err != nil {
		return
	}
	sidLen := len(sidData)

	// Marshal Ciphertext
	ctData := make([]byte, 0)
	if query.Ciphertext != nil {
		ctData, err = query.Ciphertext.MarshalBinary()
		if err != nil {
			return
		}
	}
	ctLen := len(ctData)

	// Build data as [<sidLen>, <ctLen>, <SessionID>, <Ciphertext>]
	data = make([]byte, 2*8+sidLen+ctLen)
	ptr := 0 // Used to index data
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(sidLen))
	ptr += 8
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(ctLen))
	ptr += 8
	copy(data[ptr:ptr+sidLen], sidData)
	ptr += sidLen
	copy(data[ptr:ptr+ctLen], ctData)
	ptr += ctLen

	return
}
func (query *StoreQuery) UnmarshalBinary(data []byte) (err error) {
	ptr := 0 // Used to index data

	// Read lengths
	sidLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8
	ctLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8

	// Read SessionID
	if sidLen > 0 {
		err = query.SessionID.UnmarshalBinary(data[ptr : ptr+sidLen])
		ptr += sidLen
		if err != nil {
			return
		}
	}

	// Read Ciphertext
	if ctLen > 0 {
		if query.Ciphertext == nil {
			query.Ciphertext = &bfv.Ciphertext{}
		}
		err = query.Ciphertext.UnmarshalBinary(data[ptr : ptr+ctLen])
		ptr += ctLen
		if err != nil {
			return
		}
	}

	return
}

func (resp *StoreResponse) MarshalBinary() (data []byte, err error) {
	// Marshal CipherID
	cidData := make([]byte, 0)
	cidData, err = resp.CipherID.MarshalBinary()
	if err != nil {
		return
	}
	cidLen := len(cidData)

	// Build data as [<cidLen>, <CipherID>, <valid>]
	data = make([]byte, 8+cidLen+1)
	ptr := 0 // Used to index data
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(cidLen))
	ptr += 8
	copy(data[ptr:ptr+cidLen], cidData)
	ptr += cidLen
	data[ptr] = marshBool(resp.Valid)
	ptr += 1

	return
}
func (resp *StoreResponse) UnmarshalBinary(data []byte) (err error) {
	ptr := 0 // Used to index data

	// Read lengths
	cidLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8

	// Read CipherID
	if cidLen > 0 {
		err = resp.CipherID.UnmarshalBinary(data[ptr : ptr+cidLen])
		ptr += cidLen
		if err != nil {
			return
		}
	}

	// Read Valid
	resp.Valid = unmarshBool(data[ptr])
	ptr += 1

	return
}

// Store and name

func (query *StoreAndNameQuery) MarshalBinary() (data []byte, err error) {
	// Marshal CircuitID
	cidData, err := query.CircuitID.MarshalBinary()
	if err != nil {
		return
	}
	cidLen := len(cidData)

	// Marshal Name
	nameData := []byte(query.Name)
	nameLen := len(nameData)

	// Marshal Ciphertext
	ctData := make([]byte, 0)
	if query.Ciphertext != nil {
		ctData, err = query.Ciphertext.MarshalBinary()
		if err != nil {
			return
		}
	}
	ctLen := len(ctData)

	// Build data as [<cidLen>, <nameLen>, <ctLen>, <CircuitID>, <Name>, <Ciphertext>]
	data = make([]byte, 3*8+cidLen+nameLen+ctLen)
	ptr := 0 // Used to index data
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(cidLen))
	ptr += 8
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(nameLen))
	ptr += 8
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(ctLen))
	ptr += 8
	copy(data[ptr:ptr+cidLen], cidData)
	ptr += cidLen
	copy(data[ptr:ptr+nameLen], nameData)
	ptr += nameLen
	copy(data[ptr:ptr+ctLen], ctData)
	ptr += ctLen

	return
}
func (query *StoreAndNameQuery) UnmarshalBinary(data []byte) (err error) {
	ptr := 0 // Used to index data

	// Read lengths
	cidLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8
	nameLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8
	ctLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8

	// Read CircuitID
	if cidLen > 0 {
		err = query.CircuitID.UnmarshalBinary(data[ptr : ptr+cidLen])
		ptr += cidLen
		if err != nil {
			return
		}
	}

	// Read Name
	if nameLen > 0 {
		query.Name = string(data[ptr : ptr+nameLen])
		ptr += nameLen
	}

	// Read Ciphertext
	if ctLen > 0 {
		if query.Ciphertext == nil {
			query.Ciphertext = &bfv.Ciphertext{}
		}
		err = query.Ciphertext.UnmarshalBinary(data[ptr : ptr+ctLen])
		ptr += ctLen
		if err != nil {
			return
		}
	}

	return
}

func (resp *StoreAndNameResponse) MarshalBinary() (data []byte, err error) {
	// Marshal CipherID
	cidData := make([]byte, 0)
	cidData, err = resp.CipherID.MarshalBinary()
	if err != nil {
		return
	}
	cidLen := len(cidData)

	// Build data as [<cidLen>, <CipherID>, <valid>]
	data = make([]byte, 8+cidLen+1)
	ptr := 0 // Used to index data
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(cidLen))
	ptr += 8
	copy(data[ptr:ptr+cidLen], cidData)
	ptr += cidLen
	data[ptr] = marshBool(resp.Valid)
	ptr += 1

	return
}
func (resp *StoreAndNameResponse) UnmarshalBinary(data []byte) (err error) {
	ptr := 0 // Used to index data

	// Read lengths
	cidLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8

	// Read CipherID
	if cidLen > 0 {
		err = resp.CipherID.UnmarshalBinary(data[ptr : ptr+cidLen])
		ptr += cidLen
		if err != nil {
			return
		}
	}

	// Read Valid
	resp.Valid = unmarshBool(data[ptr])
	ptr += 1

	return
}

// Name

func (query *NameQuery) MarshalBinary() (data []byte, err error) {
	// Marshal CircuitID
	circIDData, err := query.CircuitID.MarshalBinary()
	if err != nil {
		return
	}
	circIDLen := len(circIDData)

	// Marshal Name
	nameData := []byte(query.Name)
	nameLen := len(nameData)

	// Marshal CipherID
	cipIDData, err := query.CipherID.MarshalBinary()
	if err != nil {
		return
	}
	cipIDLen := len(cipIDData)

	// Build data as [<circIDLen>, <nameLen>, <cipIDLen>, <SessionID>, <Name>, <CipherID>]
	data = make([]byte, 3*8+circIDLen+nameLen+cipIDLen)
	ptr := 0 // Used to index data
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(circIDLen))
	ptr += 8
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(nameLen))
	ptr += 8
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(cipIDLen))
	ptr += 8
	copy(data[ptr:ptr+circIDLen], circIDData)
	ptr += circIDLen
	copy(data[ptr:ptr+nameLen], nameData)
	ptr += nameLen
	copy(data[ptr:ptr+cipIDLen], cipIDData)
	ptr += cipIDLen

	return
}
func (query *NameQuery) UnmarshalBinary(data []byte) (err error) {
	ptr := 0 // Used to index data

	// Read lengths
	circIDLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8
	nameLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8
	cipIDLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8

	// Read CircuitID
	if circIDLen > 0 {
		err = query.CircuitID.UnmarshalBinary(data[ptr : ptr+circIDLen])
		ptr += circIDLen
		if err != nil {
			return
		}
	}

	// Read Name
	if nameLen > 0 {
		query.Name = string(data[ptr : ptr+nameLen])
		ptr += nameLen
	}

	// Read CipherID
	if cipIDLen > 0 {
		err = query.CipherID.UnmarshalBinary(data[ptr : ptr+cipIDLen])
		ptr += cipIDLen
		if err != nil {
			return
		}
	}

	return
}

// Get Ciphertext

func (id *GetCipherRequestID) MarshalBinary() ([]byte, error) {
	return (*uuid.UUID)(id).MarshalBinary()
}
func (id *GetCipherRequestID) UnmarshalBinary(data []byte) error {
	return (*uuid.UUID)(id).UnmarshalBinary(data)
}

func (req *GetCipherRequest) MarshalBinary() (data []byte, err error) {
	// Marshal RequestID
	ridData, err := req.ReqID.MarshalBinary()
	if err != nil {
		return
	}
	ridLen := len(ridData)

	// Marshal SessionID
	sidData, err := req.SessionID.MarshalBinary()
	if err != nil {
		return
	}
	sidLen := len(sidData)

	// Marshal CipherID
	cidData, err := req.CipherID.MarshalBinary()
	if err != nil {
		return
	}
	cidLen := len(cidData)

	// Build data as [<ridLen>, <sidLen>, <cidLen>, <RequestID>, <SessionID>, <CipherID>]
	data = make([]byte, 3*8+ridLen+sidLen+cidLen)
	ptr := 0 // Used to index data
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(ridLen))
	ptr += 8
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(sidLen))
	ptr += 8
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(cidLen))
	ptr += 8
	copy(data[ptr:ptr+ridLen], ridData)
	ptr += ridLen
	copy(data[ptr:ptr+sidLen], sidData)
	ptr += sidLen
	copy(data[ptr:ptr+cidLen], cidData)
	ptr += cidLen

	return
}
func (req *GetCipherRequest) UnmarshalBinary(data []byte) (err error) {
	ptr := 0 // Used to index data

	// Read lengths
	ridLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8
	sidLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8
	cidLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8

	// Read RequestID
	if ridLen > 0 {
		err = req.ReqID.UnmarshalBinary(data[ptr : ptr+ridLen])
		ptr += ridLen
		if err != nil {
			return
		}
	}

	// Read SessionID
	if sidLen > 0 {
		err = req.SessionID.UnmarshalBinary(data[ptr : ptr+sidLen])
		ptr += sidLen
		if err != nil {
			return
		}
	}

	// Read CipherID
	if cidLen > 0 {
		err = req.CipherID.UnmarshalBinary(data[ptr : ptr+cidLen])
		ptr += cidLen
		if err != nil {
			return
		}
	}

	return
}

func (req *GetCipherReply) MarshalBinary() (data []byte, err error) {
	// Marshal RequestID
	ridData, err := req.ReqID.MarshalBinary()
	if err != nil {
		return
	}
	ridLen := len(ridData)

	// Marshal Ciphertext
	ctData := make([]byte, 0)
	if req.Ciphertext != nil {
		ctData, err = req.Ciphertext.MarshalBinary()
		if err != nil {
			return
		}
	}
	ctLen := len(ctData)

	// Build data as [<ridLen>, <ctLen>, <RequestID>, <Ciphertext>, <Valid>]
	data = make([]byte, 2*8+ridLen+ctLen+1)
	ptr := 0 // Used to index data
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(ridLen))
	ptr += 8
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(ctLen))
	ptr += 8
	copy(data[ptr:ptr+ridLen], ridData)
	ptr += ridLen
	copy(data[ptr:ptr+ctLen], ctData)
	ptr += ctLen
	data[ptr] = marshBool(req.Valid)
	ptr += 1

	return
}
func (req *GetCipherReply) UnmarshalBinary(data []byte) (err error) {
	ptr := 0 // Used to index data

	// Read lengths
	ridLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8
	ctLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8

	// Read RequestID
	if ridLen > 0 {
		err = req.ReqID.UnmarshalBinary(data[ptr : ptr+ridLen])
		ptr += ridLen
		if err != nil {
			return
		}
	}

	// Read Ciphertext
	if ctLen > 0 {
		if req.Ciphertext == nil {
			req.Ciphertext = &bfv.Ciphertext{}
		}
		err = req.Ciphertext.UnmarshalBinary(data[ptr : ptr+ctLen])
		ptr += ctLen
		if err != nil {
			return
		}
	}

	// Read Valid
	req.Valid = unmarshBool(data[ptr])
	ptr += 1

	return
}

// Get CipherID

func (id *GetCipherIDRequestID) MarshalBinary() ([]byte, error) {
	return (*uuid.UUID)(id).MarshalBinary()
}
func (id *GetCipherIDRequestID) UnmarshalBinary(data []byte) error {
	return (*uuid.UUID)(id).UnmarshalBinary(data)
}

func (req *GetCipherIDReply) MarshalBinary() (data []byte, err error) {
	// Marshal RequestID
	ridData, err := req.ReqID.MarshalBinary()
	if err != nil {
		return
	}
	ridLen := len(ridData)

	// Marshal CipherID
	cidData := make([]byte, 0)
	cidData, err = req.CipherID.MarshalBinary()
	if err != nil {
		return
	}
	cidLen := len(cidData)

	// Build data as [<ridLen>, <cidLen>, <RequestID>, <Ciphertext>, <Valid>]
	data = make([]byte, 2*8+ridLen+cidLen+1)
	ptr := 0 // Used to index data
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(ridLen))
	ptr += 8
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(cidLen))
	ptr += 8
	copy(data[ptr:ptr+ridLen], ridData)
	ptr += ridLen
	copy(data[ptr:ptr+cidLen], cidData)
	ptr += cidLen
	data[ptr] = marshBool(req.Valid)
	ptr += 1

	return
}
func (req *GetCipherIDReply) UnmarshalBinary(data []byte) (err error) {
	ptr := 0 // Used to index data

	// Read lengths
	ridLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8
	cidLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8

	// Read RequestID
	if ridLen > 0 {
		err = req.ReqID.UnmarshalBinary(data[ptr : ptr+ridLen])
		ptr += ridLen
		if err != nil {
			return
		}
	}

	// Read Ciphertext
	if cidLen > 0 {
		err = req.CipherID.UnmarshalBinary(data[ptr : ptr+cidLen])
		ptr += cidLen
		if err != nil {
			return
		}
	}

	// Read Valid
	req.Valid = unmarshBool(data[ptr])
	ptr += 1

	return
}

// Retrieve

func (query *SwitchQuery) MarshalBinary() (data []byte, err error) {
	// Marshal SessionID
	sidData, err := query.SessionID.MarshalBinary()
	if err != nil {
		return
	}
	sidLen := len(sidData)

	// Marshal CipherID
	cidData, err := query.CipherID.MarshalBinary()
	if err != nil {
		return
	}
	cidLen := len(cidData)

	// Marshal PublicKey
	pkData := make([]byte, 0)
	if query.PublicKey != nil {
		pkData, err = query.PublicKey.MarshalBinary()
		if err != nil {
			return
		}
	}
	pkLen := len(pkData)

	// Build data as [<sidLen>, <cidLen>, <pkLen>, <SessionID>, <CipherID>, <PublicKey>]
	data = make([]byte, 3*8+sidLen+cidLen+pkLen)
	ptr := 0 // Used to index data
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(sidLen))
	ptr += 8
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(cidLen))
	ptr += 8
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(pkLen))
	ptr += 8
	copy(data[ptr:ptr+sidLen], sidData)
	ptr += sidLen
	copy(data[ptr:ptr+cidLen], cidData)
	ptr += cidLen
	copy(data[ptr:ptr+pkLen], pkData)
	ptr += pkLen

	return
}
func (query *SwitchQuery) UnmarshalBinary(data []byte) (err error) {
	ptr := 0 // Used to index data

	// Read lengths
	sidLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8
	cidLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8
	pkLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8

	// Read SessionID
	if sidLen > 0 {
		err = query.SessionID.UnmarshalBinary(data[ptr : ptr+sidLen])
		ptr += sidLen
		if err != nil {
			return
		}
	}

	// Read CipherID
	if cidLen > 0 {
		err = query.CipherID.UnmarshalBinary(data[ptr : ptr+cidLen])
		ptr += cidLen
		if err != nil {
			return
		}
	}

	// Read PublicKey
	if pkLen > 0 {
		if query.PublicKey == nil {
			query.PublicKey = &bfv.PublicKey{}
		}
		err = query.PublicKey.UnmarshalBinary(data[ptr : ptr+pkLen])
		ptr += pkLen
		if err != nil {
			return
		}
	}

	return
}

func (id *SwitchRequestID) MarshalBinary() ([]byte, error) {
	return (*uuid.UUID)(id).MarshalBinary()
}
func (id *SwitchRequestID) UnmarshalBinary(data []byte) error {
	return (*uuid.UUID)(id).UnmarshalBinary(data)
}

func (req *SwitchRequest) MarshalBinary() (data []byte, err error) {
	// Marshal RequestID
	ridData, err := req.ReqID.MarshalBinary()
	if err != nil {
		return
	}
	ridLen := len(ridData)

	// Marshal SessionID
	sidData, err := req.SessionID.MarshalBinary()
	if err != nil {
		return
	}
	sidLen := len(sidData)

	// Marshal CipherID
	cidData, err := req.CipherID.MarshalBinary()
	if err != nil {
		return
	}
	cidLen := len(cidData)

	// Marshal PublicKey
	pkData := make([]byte, 0)
	if req.PublicKey != nil {
		pkData, err = req.PublicKey.MarshalBinary()
		if err != nil {
			return
		}
	}
	pkLen := len(pkData)

	// Build data as [<ridLen>, <sidLen>, <cidLen>, <pkLen>, <RequestID>, <SessionID>, <CipherID>, <PublicKey>]
	data = make([]byte, 4*8+ridLen+sidLen+cidLen+pkLen)
	ptr := 0 // Used to index data
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(ridLen))
	ptr += 8
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(sidLen))
	ptr += 8
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(cidLen))
	ptr += 8
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(pkLen))
	ptr += 8
	copy(data[ptr:ptr+sidLen], ridData)
	ptr += sidLen
	copy(data[ptr:ptr+ridLen], sidData)
	ptr += ridLen
	copy(data[ptr:ptr+cidLen], cidData)
	ptr += cidLen
	copy(data[ptr:ptr+pkLen], pkData)
	ptr += pkLen

	return
}
func (req *SwitchRequest) UnmarshalBinary(data []byte) (err error) {
	ptr := 0 // Used to index data

	// Read lengths
	ridLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8
	sidLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8
	cidLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8
	pkLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8

	// Read RequestID
	if ridLen > 0 {
		err = req.ReqID.UnmarshalBinary(data[ptr : ptr+ridLen])
		ptr += ridLen
		if err != nil {
			return
		}
	}

	// Read SessionID
	if sidLen > 0 {
		err = req.SessionID.UnmarshalBinary(data[ptr : ptr+sidLen])
		ptr += sidLen
		if err != nil {
			return
		}
	}

	// Read CipherID
	if cidLen > 0 {
		err = req.CipherID.UnmarshalBinary(data[ptr : ptr+cidLen])
		ptr += cidLen
		if err != nil {
			return
		}
	}

	// Read PublicKey
	if pkLen > 0 {
		if req.PublicKey == nil {
			req.PublicKey = &bfv.PublicKey{}
		}
		err = req.PublicKey.UnmarshalBinary(data[ptr : ptr+pkLen])
		ptr += pkLen
		if err != nil {
			return
		}
	}

	return
}

func (cfg *SwitchConfig) MarshalBinary() (data []byte, err error) {
	// Marshal SessionID
	sidData, err := cfg.SessionID.MarshalBinary()
	if err != nil {
		return
	}
	sidLen := len(sidData)

	// Marshal PublicKey
	pkData, err := cfg.PublicKey.MarshalBinary()
	if err != nil {
		return
	}
	pkLen := len(pkData)

	// Marshal Ciphertext
	ctData, err := cfg.Ciphertext.MarshalBinary()
	if err != nil {
		return
	}
	ctLen := len(ctData)

	// Build data as [<sidLen>, <cidLen>, <ctLen>, <SessionID>, <CipherID>, <Ciphertext>]
	data = make([]byte, 8+8+8+sidLen+pkLen+ctLen)
	ptr := 0 // Used to index data
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(sidLen))
	ptr += 8
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(pkLen))
	ptr += 8
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(ctLen))
	ptr += 8
	copy(data[ptr:ptr+sidLen], sidData)
	ptr += sidLen
	copy(data[ptr:ptr+pkLen], pkData)
	ptr += pkLen
	copy(data[ptr:ptr+ctLen], ctData)
	ptr += ctLen

	return
}
func (cfg *SwitchConfig) UnmarshalBinary(data []byte) (err error) {
	ptr := 0 // Used to index data

	// Read lengths
	sidLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8
	pkLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8
	ctLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8

	// Read SessionID
	if sidLen > 0 {
		err = cfg.SessionID.UnmarshalBinary(data[ptr : ptr+sidLen])
		ptr += sidLen
		if err != nil {
			return
		}
	}

	// Read PublicKey
	if pkLen > 0 {
		if cfg.PublicKey == nil {
			cfg.PublicKey = &bfv.PublicKey{}
		}
		err = cfg.PublicKey.UnmarshalBinary(data[ptr : ptr+pkLen])
		ptr += pkLen
		if err != nil {
			return
		}
	}

	// Read Ciphertext
	if ctLen > 0 {
		if cfg.Ciphertext == nil {
			cfg.Ciphertext = &bfv.Ciphertext{}
		}
		err = cfg.Ciphertext.UnmarshalBinary(data[ptr : ptr+ctLen])
		ptr += ctLen
		if err != nil {
			return
		}
	}

	return
}

func (reply *SwitchReply) MarshalBinary() (data []byte, err error) {
	// Marshal SessionID
	sidData, err := reply.SessionID.MarshalBinary()
	if err != nil {
		return
	}
	sidLen := len(sidData)

	// Marshal RequestID
	ridData, err := reply.ReqID.MarshalBinary()
	if err != nil {
		return
	}
	ridLen := len(ridData)

	// Marshal Ciphertext
	ctData := make([]byte, 0)
	if reply.Ciphertext != nil {
		ctData, err = reply.Ciphertext.MarshalBinary()
		if err != nil {
			return
		}
	}
	ctLen := len(ctData)

	// Build data as [<sidLen>, <ridLen>, <ctLen>, <SessionID>, <RequestID>, <Ciphertext>, <Valid>]
	data = make([]byte, 3*8+sidLen+ridLen+ctLen+1)
	ptr := 0 // Used to index data
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(sidLen))
	ptr += 8
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(ridLen))
	ptr += 8
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(ctLen))
	ptr += 8
	copy(data[ptr:ptr+sidLen], sidData)
	ptr += sidLen
	copy(data[ptr:ptr+ridLen], ridData)
	ptr += ridLen
	copy(data[ptr:ptr+ctLen], ctData)
	ptr += ctLen
	data[ptr] = marshBool(reply.Valid)
	ptr += 1

	return
}
func (reply *SwitchReply) UnmarshalBinary(data []byte) (err error) {
	ptr := 0 // Used to index data

	// Read lengths
	sidLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8
	ridLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8
	ctLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8

	// Read SessionID
	if sidLen > 0 {
		err = reply.SessionID.UnmarshalBinary(data[ptr : ptr+sidLen])
		ptr += sidLen
		if err != nil {
			return
		}
	}

	// Read RequestID
	if ridLen > 0 {
		err = reply.ReqID.UnmarshalBinary(data[ptr : ptr+ridLen])
		ptr += ridLen
		if err != nil {
			return
		}
	}

	// Read Ciphertext
	if ctLen > 0 {
		if reply.Ciphertext == nil {
			reply.Ciphertext = &bfv.Ciphertext{}
		}
		err = reply.Ciphertext.UnmarshalBinary(data[ptr : ptr+ctLen])
		ptr += ctLen
		if err != nil {
			return
		}
	}

	// Read Valid
	reply.Valid = unmarshBool(data[ptr])
	ptr += 1

	return
}

func (resp *SwitchResponse) MarshalBinary() (data []byte, err error) {
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
func (resp *SwitchResponse) UnmarshalBinary(data []byte) (err error) {
	ptr := 0 // Used to index data

	// Read lengths
	ctLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8

	// Read Ciphertext
	if ctLen > 0 {
		if resp.Ciphertext == nil {
			resp.Ciphertext = &bfv.Ciphertext{}
		}
		err = resp.Ciphertext.UnmarshalBinary(data[ptr : ptr+ctLen])
		ptr += ctLen
		if err != nil {
			return
		}
	}

	// Read Valid
	resp.Valid = unmarshBool(data[ptr])
	ptr += 1

	return
}

// Sum

func (id *SumRequestID) MarshalBinary() ([]byte, error) {
	return (*uuid.UUID)(id).MarshalBinary()
}
func (id *SumRequestID) UnmarshalBinary(data []byte) error {
	return (*uuid.UUID)(id).UnmarshalBinary(data)
}

func (req *SumRequest) MarshalBinary() (data []byte, err error) {
	// Marshal RequestID
	ridData, err := req.ReqID.MarshalBinary()
	if err != nil {
		return
	}
	ridLen := len(ridData)

	// Marshal SessionID
	sidData, err := req.SessionID.MarshalBinary()
	if err != nil {
		return
	}
	sidLen := len(sidData)

	// Marshal CipherID1
	cid1Data, err := req.CipherID1.MarshalBinary()
	if err != nil {
		return
	}
	cid1Len := len(cid1Data)

	// Marshal CipherID2
	cid2Data, err := req.CipherID2.MarshalBinary()
	if err != nil {
		return
	}
	cid2Len := len(cid2Data)

	// Build data as [<ridLen>, <sidLen>, <cid1Len>, <cid2Len>, <RequestID>, <SessionID>, <CipherID1>, <CipherID2>]
	data = make([]byte, 4*8+ridLen+sidLen+cid1Len+cid2Len)
	ptr := 0 // Used to index data
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(ridLen))
	ptr += 8
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(sidLen))
	ptr += 8
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(cid1Len))
	ptr += 8
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(cid2Len))
	ptr += 8
	copy(data[ptr:ptr+sidLen], ridData)
	ptr += sidLen
	copy(data[ptr:ptr+ridLen], sidData)
	ptr += ridLen
	copy(data[ptr:ptr+cid1Len], cid1Data)
	ptr += cid1Len
	copy(data[ptr:ptr+cid2Len], cid2Data)
	ptr += cid2Len

	return
}
func (req *SumRequest) UnmarshalBinary(data []byte) (err error) {
	ptr := 0 // Used to index data

	// Read lengths
	ridLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8
	sidLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8
	cid1Len := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8
	cid2Len := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8

	// Read RequestID
	if ridLen > 0 {
		err = req.ReqID.UnmarshalBinary(data[ptr : ptr+ridLen])
		ptr += ridLen
		if err != nil {
			return
		}
	}

	// Read SessionID
	if sidLen > 0 {
		err = req.SessionID.UnmarshalBinary(data[ptr : ptr+sidLen])
		ptr += sidLen
		if err != nil {
			return
		}
	}

	// Read CipherID1
	if cid1Len > 0 {
		err = req.CipherID1.UnmarshalBinary(data[ptr : ptr+cid1Len])
		ptr += cid1Len
		if err != nil {
			return
		}
	}

	// Read CipherID2
	if cid1Len > 0 {
		err = req.CipherID2.UnmarshalBinary(data[ptr : ptr+cid2Len])
		ptr += cid2Len
		if err != nil {
			return
		}
	}

	return
}

func (reply *SumReply) MarshalBinary() (data []byte, err error) {
	// Marshal RequestID
	ridData, err := reply.ReqID.MarshalBinary()
	if err != nil {
		return
	}
	ridLen := len(ridData)

	// Marshal SessionID
	sidData, err := reply.SessionID.MarshalBinary()
	if err != nil {
		return
	}
	sidLen := len(sidData)

	// Marshal NewCipherID
	cidData := make([]byte, 0)
	cidData, err = reply.NewCipherID.MarshalBinary()
	if err != nil {
		return
	}
	cidLen := len(cidData)

	// Build data as [<ridLen>, <sidLen>, <cidLen>, <RequestID>, <SessionID>, <CipherID>, <Valid>]
	data = make([]byte, 3*8+ridLen+sidLen+cidLen+1)
	ptr := 0 // Used to index data
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(ridLen))
	ptr += 8
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(sidLen))
	ptr += 8
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(cidLen))
	ptr += 8
	copy(data[ptr:ptr+ridLen], ridData)
	ptr += ridLen
	copy(data[ptr:ptr+sidLen], sidData)
	ptr += sidLen
	copy(data[ptr:ptr+cidLen], cidData)
	ptr += cidLen
	data[ptr] = marshBool(reply.Valid)
	ptr += 1

	return
}
func (reply *SumReply) UnmarshalBinary(data []byte) (err error) {
	ptr := 0 // Used to index data

	// Read lengths
	ridLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8
	sidLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8
	cidLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8

	// Read RequestID
	if ridLen > 0 {
		err = reply.ReqID.UnmarshalBinary(data[ptr : ptr+ridLen])
		ptr += ridLen
		if err != nil {
			return
		}
	}

	// Read SessionID
	if sidLen > 0 {
		err = reply.SessionID.UnmarshalBinary(data[ptr : ptr+sidLen])
		ptr += sidLen
		if err != nil {
			return
		}
	}

	// Read CipherID
	if cidLen > 0 {
		err = reply.NewCipherID.UnmarshalBinary(data[ptr : ptr+cidLen])
		ptr += cidLen
		if err != nil {
			return
		}
	}

	// Read Valid
	reply.Valid = unmarshBool(data[ptr])
	ptr += 1

	return
}

// Multiply

func (id *MultiplyRequestID) MarshalBinary() ([]byte, error) {
	return (*uuid.UUID)(id).MarshalBinary()
}
func (id *MultiplyRequestID) UnmarshalBinary(data []byte) error {
	return (*uuid.UUID)(id).UnmarshalBinary(data)
}

func (req *MultiplyRequest) MarshalBinary() (data []byte, err error) {
	// Marshal RequestID
	ridData, err := req.ReqID.MarshalBinary()
	if err != nil {
		return
	}
	ridLen := len(ridData)

	// Marshal SessionID
	sidData, err := req.SessionID.MarshalBinary()
	if err != nil {
		return
	}
	sidLen := len(sidData)

	// Marshal CipherID1
	cid1Data, err := req.CipherID1.MarshalBinary()
	if err != nil {
		return
	}
	cid1Len := len(cid1Data)

	// Marshal CipherID2
	cid2Data, err := req.CipherID2.MarshalBinary()
	if err != nil {
		return
	}
	cid2Len := len(cid2Data)

	// Build data as [<ridLen>, <sidLen>, <cid1Len>, <cid2Len>, <RequestID>, <SessionID>, <CipherID1>, <CipherID2>, <WithRelin>]
	data = make([]byte, 4*8+ridLen+sidLen+cid1Len+cid2Len+1)
	ptr := 0 // Used to index data
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(ridLen))
	ptr += 8
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(sidLen))
	ptr += 8
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(cid1Len))
	ptr += 8
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(cid2Len))
	ptr += 8
	copy(data[ptr:ptr+sidLen], ridData)
	ptr += sidLen
	copy(data[ptr:ptr+ridLen], sidData)
	ptr += ridLen
	copy(data[ptr:ptr+cid1Len], cid1Data)
	ptr += cid1Len
	copy(data[ptr:ptr+cid2Len], cid2Data)
	ptr += cid2Len
	data[ptr] = marshBool(req.WithRelin)
	ptr += 1

	return
}
func (req *MultiplyRequest) UnmarshalBinary(data []byte) (err error) {
	ptr := 0 // Used to index data

	// Read lengths
	ridLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8
	sidLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8
	cid1Len := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8
	cid2Len := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8

	// Read RequestID
	if ridLen > 0 {
		err = req.ReqID.UnmarshalBinary(data[ptr : ptr+ridLen])
		ptr += ridLen
		if err != nil {
			return
		}
	}

	// Read SessionID
	if sidLen > 0 {
		err = req.SessionID.UnmarshalBinary(data[ptr : ptr+sidLen])
		ptr += sidLen
		if err != nil {
			return
		}
	}

	// Read CipherID1
	if cid1Len > 0 {
		err = req.CipherID1.UnmarshalBinary(data[ptr : ptr+cid1Len])
		ptr += cid1Len
		if err != nil {
			return
		}
	}

	// Read CipherID2
	if cid1Len > 0 {
		err = req.CipherID2.UnmarshalBinary(data[ptr : ptr+cid2Len])
		ptr += cid2Len
		if err != nil {
			return
		}
	}

	// Read WithRelin
	req.WithRelin = unmarshBool(data[ptr])
	ptr += 1

	return
}

func (reply *MultiplyReply) MarshalBinary() (data []byte, err error) {
	// Marshal RequestID
	ridData, err := reply.ReqID.MarshalBinary()
	if err != nil {
		return
	}
	ridLen := len(ridData)

	// Marshal SessionID
	sidData, err := reply.SessionID.MarshalBinary()
	if err != nil {
		return
	}
	sidLen := len(sidData)

	// Marshal NewCipherID
	cidData := make([]byte, 0)
	cidData, err = reply.NewCipherID.MarshalBinary()
	if err != nil {
		return
	}
	cidLen := len(cidData)

	// Build data as [<ridLen>, <sidLen>, <cidLen>, <RequestID>, <SessionID>, <CipherID>, <Valid>]
	data = make([]byte, 3*8+ridLen+sidLen+cidLen+1)
	ptr := 0 // Used to index data
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(ridLen))
	ptr += 8
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(sidLen))
	ptr += 8
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(cidLen))
	ptr += 8
	copy(data[ptr:ptr+ridLen], ridData)
	ptr += ridLen
	copy(data[ptr:ptr+sidLen], sidData)
	ptr += sidLen
	copy(data[ptr:ptr+cidLen], cidData)
	ptr += cidLen
	data[ptr] = marshBool(reply.Valid)
	ptr += 1

	return
}
func (reply *MultiplyReply) UnmarshalBinary(data []byte) (err error) {
	ptr := 0 // Used to index data

	// Read lengths
	ridLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8
	sidLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8
	cidLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8

	// Read RequestID
	if ridLen > 0 {
		err = reply.ReqID.UnmarshalBinary(data[ptr : ptr+ridLen])
		ptr += ridLen
		if err != nil {
			return
		}
	}

	// Read SessionID
	if sidLen > 0 {
		err = reply.SessionID.UnmarshalBinary(data[ptr : ptr+sidLen])
		ptr += sidLen
		if err != nil {
			return
		}
	}

	// Read CipherID
	if cidLen > 0 {
		err = reply.NewCipherID.UnmarshalBinary(data[ptr : ptr+cidLen])
		ptr += cidLen
		if err != nil {
			return
		}
	}

	// Read Valid
	reply.Valid = unmarshBool(data[ptr])
	ptr += 1

	return
}

// Relinearise

func (id *RelinRequestID) MarshalBinary() ([]byte, error) {
	return (*uuid.UUID)(id).MarshalBinary()
}
func (id *RelinRequestID) UnmarshalBinary(data []byte) error {
	return (*uuid.UUID)(id).UnmarshalBinary(data)
}

func (req *RelinRequest) MarshalBinary() (data []byte, err error) {
	// Marshal RequestID
	ridData, err := req.ReqID.MarshalBinary()
	if err != nil {
		return
	}
	ridLen := len(ridData)

	// Marshal SessionID
	sidData, err := req.SessionID.MarshalBinary()
	if err != nil {
		return
	}
	sidLen := len(sidData)

	// Marshal CipherID
	cidData, err := req.CipherID.MarshalBinary()
	if err != nil {
		return
	}
	cidLen := len(cidData)

	// Build data as [<ridLen>, <sidLen>, <cidLen>, <RequestID>, <SessionID>, <CipherID>]
	data = make([]byte, 3*8+ridLen+sidLen+cidLen)
	ptr := 0 // Used to index data
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(ridLen))
	ptr += 8
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(sidLen))
	ptr += 8
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(cidLen))
	ptr += 8
	copy(data[ptr:ptr+sidLen], ridData)
	ptr += sidLen
	copy(data[ptr:ptr+ridLen], sidData)
	ptr += ridLen
	copy(data[ptr:ptr+cidLen], cidData)
	ptr += cidLen

	return
}
func (req *RelinRequest) UnmarshalBinary(data []byte) (err error) {
	ptr := 0 // Used to index data

	// Read lengths
	ridLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8
	sidLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8
	cidLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8

	// Read RequestID
	if ridLen > 0 {
		err = req.ReqID.UnmarshalBinary(data[ptr : ptr+ridLen])
		ptr += ridLen
		if err != nil {
			return
		}
	}

	// Read SessionID
	if sidLen > 0 {
		err = req.SessionID.UnmarshalBinary(data[ptr : ptr+sidLen])
		ptr += sidLen
		if err != nil {
			return
		}
	}

	// Read CipherID
	if cidLen > 0 {
		err = req.CipherID.UnmarshalBinary(data[ptr : ptr+cidLen])
		ptr += cidLen
		if err != nil {
			return
		}
	}

	return
}

func (reply *RelinReply) MarshalBinary() (data []byte, err error) {
	// Marshal RequestID
	ridData, err := reply.ReqID.MarshalBinary()
	if err != nil {
		return
	}
	ridLen := len(ridData)

	// Marshal SessionID
	sidData, err := reply.SessionID.MarshalBinary()
	if err != nil {
		return
	}
	sidLen := len(sidData)

	// Marshal NewCipherID
	cidData := make([]byte, 0)
	cidData, err = reply.NewCipherID.MarshalBinary()
	if err != nil {
		return
	}
	cidLen := len(cidData)

	// Build data as [<ridLen>, <sidLen>, <cidLen>, <RequestID>, <SessionID>, <CipherID>, <Valid>]
	data = make([]byte, 3*8+ridLen+sidLen+cidLen+1)
	ptr := 0 // Used to index data
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(ridLen))
	ptr += 8
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(sidLen))
	ptr += 8
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(cidLen))
	ptr += 8
	copy(data[ptr:ptr+ridLen], ridData)
	ptr += ridLen
	copy(data[ptr:ptr+sidLen], sidData)
	ptr += sidLen
	copy(data[ptr:ptr+cidLen], cidData)
	ptr += cidLen
	data[ptr] = marshBool(reply.Valid)
	ptr += 1

	return
}
func (reply *RelinReply) UnmarshalBinary(data []byte) (err error) {
	ptr := 0 // Used to index data

	// Read lengths
	ridLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8
	sidLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8
	cidLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8

	// Read RequestID
	if ridLen > 0 {
		err = reply.ReqID.UnmarshalBinary(data[ptr : ptr+ridLen])
		ptr += ridLen
		if err != nil {
			return
		}
	}

	// Read SessionID
	if sidLen > 0 {
		err = reply.SessionID.UnmarshalBinary(data[ptr : ptr+sidLen])
		ptr += sidLen
		if err != nil {
			return
		}
	}

	// Read CipherID
	if cidLen > 0 {
		err = reply.NewCipherID.UnmarshalBinary(data[ptr : ptr+cidLen])
		ptr += cidLen
		if err != nil {
			return
		}
	}

	// Read Valid
	reply.Valid = unmarshBool(data[ptr])
	ptr += 1

	return
}

// Refresh

func (id *RefreshRequestID) MarshalBinary() ([]byte, error) {
	return (*uuid.UUID)(id).MarshalBinary()
}
func (id *RefreshRequestID) UnmarshalBinary(data []byte) error {
	return (*uuid.UUID)(id).UnmarshalBinary(data)
}

func (req *RefreshRequest) MarshalBinary() (data []byte, err error) {
	// Marshal RequestID
	ridData, err := req.ReqID.MarshalBinary()
	if err != nil {
		return
	}
	ridLen := len(ridData)

	// Marshal SessionID
	sidData, err := req.SessionID.MarshalBinary()
	if err != nil {
		return
	}
	sidLen := len(sidData)

	// Marshal CipherID
	cidData, err := req.CipherID.MarshalBinary()
	if err != nil {
		return
	}
	cidLen := len(cidData)

	// Marshal Seed
	seedLen := len(req.Seed)

	// Build data as [<ridLen>, <sidLen>, <cidLen>, <seedLen>, <RequestID>, <SessionID>, <CipherID>, <Seed>]
	data = make([]byte, 4*8+ridLen+sidLen+cidLen+seedLen)
	ptr := 0 // Used to index data
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(ridLen))
	ptr += 8
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(sidLen))
	ptr += 8
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(cidLen))
	ptr += 8
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(seedLen))
	ptr += 8
	copy(data[ptr:ptr+sidLen], ridData)
	ptr += sidLen
	copy(data[ptr:ptr+ridLen], sidData)
	ptr += ridLen
	copy(data[ptr:ptr+cidLen], cidData)
	ptr += cidLen
	copy(data[ptr:ptr+seedLen], req.Seed)
	ptr += seedLen

	return
}
func (req *RefreshRequest) UnmarshalBinary(data []byte) (err error) {
	ptr := 0 // Used to index data

	// Read lengths
	ridLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8
	sidLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8
	cidLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8
	seedLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8

	// Read RequestID
	if ridLen > 0 {
		err = req.ReqID.UnmarshalBinary(data[ptr : ptr+ridLen])
		ptr += ridLen
		if err != nil {
			return
		}
	}

	// Read SessionID
	if sidLen > 0 {
		err = req.SessionID.UnmarshalBinary(data[ptr : ptr+sidLen])
		ptr += sidLen
		if err != nil {
			return
		}
	}

	// Read CipherID
	if cidLen > 0 {
		err = req.CipherID.UnmarshalBinary(data[ptr : ptr+cidLen])
		ptr += cidLen
		if err != nil {
			return
		}
	}

	// Read Seed
	req.Seed = make([]byte, seedLen)
	copy(req.Seed, data[ptr:ptr+seedLen])
	ptr += seedLen

	return
}

func (cfg *RefreshConfig) MarshalBinary() (data []byte, err error) {
	// Marshal SessionID
	sidData, err := cfg.SessionID.MarshalBinary()
	if err != nil {
		return
	}
	sidLen := len(sidData)

	// Marshal Ciphertext
	ctData, err := cfg.Ciphertext.MarshalBinary()
	if err != nil {
		return
	}
	ctLen := len(ctData)

	// Marshal Seed
	seedLen := len(cfg.Seed)

	// Build data as [<sidLen>, <ctLen>, <seedLen>, <SessionID>, <Ciphertext>, <Seed>]
	data = make([]byte, 3*8+sidLen+ctLen+seedLen)
	ptr := 0 // Used to index data
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(sidLen))
	ptr += 8
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(ctLen))
	ptr += 8
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(seedLen))
	ptr += 8
	copy(data[ptr:ptr+sidLen], sidData)
	ptr += sidLen
	copy(data[ptr:ptr+ctLen], ctData)
	ptr += ctLen
	copy(data[ptr:ptr+seedLen], cfg.Seed)
	ptr += seedLen

	return
}
func (cfg *RefreshConfig) UnmarshalBinary(data []byte) (err error) {
	ptr := 0 // Used to index data

	// Read lengths
	sidLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8
	ctLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8
	seedLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8

	// Read SessionID
	if sidLen > 0 {
		err = cfg.SessionID.UnmarshalBinary(data[ptr : ptr+sidLen])
		ptr += sidLen
		if err != nil {
			return
		}
	}

	// Read Ciphertext
	if ctLen > 0 {
		if cfg.Ciphertext == nil {
			cfg.Ciphertext = &bfv.Ciphertext{}
		}
		err = cfg.Ciphertext.UnmarshalBinary(data[ptr : ptr+ctLen])
		ptr += ctLen
		if err != nil {
			return
		}
	}

	// Read Seed
	cfg.Seed = make([]byte, seedLen)
	copy(cfg.Seed, data[ptr:ptr+seedLen])
	ptr += seedLen

	return
}

func (reply *RefreshReply) MarshalBinary() (data []byte, err error) {
	// Marshal RequestID
	ridData, err := reply.ReqID.MarshalBinary()
	if err != nil {
		return
	}
	ridLen := len(ridData)

	// Marshal SessionID
	sidData, err := reply.SessionID.MarshalBinary()
	if err != nil {
		return
	}
	sidLen := len(sidData)

	// Marshal NewCipherID
	cidData := make([]byte, 0)
	cidData, err = reply.NewCipherID.MarshalBinary()
	if err != nil {
		return
	}
	cidLen := len(cidData)

	// Build data as [<ridLen>, <sidLen>, <cidLen>, <RequestID>, <SessionID>, <CipherID>, <Valid>]
	data = make([]byte, 3*8+ridLen+sidLen+cidLen+1)
	ptr := 0 // Used to index data
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(ridLen))
	ptr += 8
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(sidLen))
	ptr += 8
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(cidLen))
	ptr += 8
	copy(data[ptr:ptr+ridLen], ridData)
	ptr += ridLen
	copy(data[ptr:ptr+sidLen], sidData)
	ptr += sidLen
	copy(data[ptr:ptr+cidLen], cidData)
	ptr += cidLen
	data[ptr] = marshBool(reply.Valid)
	ptr += 1

	return
}
func (reply *RefreshReply) UnmarshalBinary(data []byte) (err error) {
	ptr := 0 // Used to index data

	// Read lengths
	ridLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8
	sidLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8
	cidLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8

	// Read RequestID
	if ridLen > 0 {
		err = reply.ReqID.UnmarshalBinary(data[ptr : ptr+ridLen])
		ptr += ridLen
		if err != nil {
			return
		}
	}

	// Read SessionID
	if sidLen > 0 {
		err = reply.SessionID.UnmarshalBinary(data[ptr : ptr+sidLen])
		ptr += sidLen
		if err != nil {
			return
		}
	}

	// Read CipherID
	if cidLen > 0 {
		err = reply.NewCipherID.UnmarshalBinary(data[ptr : ptr+cidLen])
		ptr += cidLen
		if err != nil {
			return
		}
	}

	// Read Valid
	reply.Valid = unmarshBool(data[ptr])
	ptr += 1

	return
}

// Rotation

func (id *RotationRequestID) MarshalBinary() ([]byte, error) {
	return (*uuid.UUID)(id).MarshalBinary()
}
func (id *RotationRequestID) UnmarshalBinary(data []byte) error {
	return (*uuid.UUID)(id).UnmarshalBinary(data)
}

func (req *RotationRequest) MarshalBinary() (data []byte, err error) {
	// Marshal RequestID
	ridData, err := req.ReqID.MarshalBinary()
	if err != nil {
		return
	}
	ridLen := len(ridData)

	// Marshal SessionID
	sidData, err := req.SessionID.MarshalBinary()
	if err != nil {
		return
	}
	sidLen := len(sidData)

	// Marshal CipherID
	cidData, err := req.CipherID.MarshalBinary()
	if err != nil {
		return
	}
	cidLen := len(cidData)

	// Build data as [<ridLen>, <sidLen>, <cidLen>, <RequestID>, <SessionID>, <CipherID>, <K>, <RotIdx>]
	data = make([]byte, 3*8+ridLen+sidLen+cidLen+2*8)
	ptr := 0 // Used to index data
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(ridLen))
	ptr += 8
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(sidLen))
	ptr += 8
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(cidLen))
	ptr += 8
	copy(data[ptr:ptr+sidLen], ridData)
	ptr += sidLen
	copy(data[ptr:ptr+ridLen], sidData)
	ptr += ridLen
	copy(data[ptr:ptr+cidLen], cidData)
	ptr += cidLen
	binary.BigEndian.PutUint64(data[ptr:ptr+8], req.K)
	ptr += 8
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(req.RotIdx))
	ptr += 8

	return
}
func (req *RotationRequest) UnmarshalBinary(data []byte) (err error) {
	ptr := 0 // Used to index data

	// Read lengths
	ridLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8
	sidLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8
	cidLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8

	// Read RequestID
	if ridLen > 0 {
		err = req.ReqID.UnmarshalBinary(data[ptr : ptr+ridLen])
		ptr += ridLen
		if err != nil {
			return
		}
	}

	// Read SessionID
	if sidLen > 0 {
		err = req.SessionID.UnmarshalBinary(data[ptr : ptr+sidLen])
		ptr += sidLen
		if err != nil {
			return
		}
	}

	// Read CipherID
	if cidLen > 0 {
		err = req.CipherID.UnmarshalBinary(data[ptr : ptr+cidLen])
		ptr += cidLen
		if err != nil {
			return
		}
	}

	// Read K
	req.K = binary.BigEndian.Uint64(data[ptr : ptr+8])
	ptr += 8

	// Read RotIdx
	req.RotIdx = int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8

	return
}

func (reply *RotationReply) MarshalBinary() (data []byte, err error) {
	// Marshal RequestID
	ridData, err := reply.ReqID.MarshalBinary()
	if err != nil {
		return
	}
	ridLen := len(ridData)

	// Marshal SessionID
	sidData, err := reply.SessionID.MarshalBinary()
	if err != nil {
		return
	}
	sidLen := len(sidData)

	// Marshal NewCipherID
	cidData := make([]byte, 0)
	cidData, err = reply.NewCipherID.MarshalBinary()
	if err != nil {
		return
	}
	cidLen := len(cidData)

	// Build data as [<ridLen>, <sidLen>, <cidLen>, <RequestID>, <SessionID>, <CipherID>, <Valid>]
	data = make([]byte, 3*8+ridLen+sidLen+cidLen+1)
	ptr := 0 // Used to index data
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(ridLen))
	ptr += 8
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(sidLen))
	ptr += 8
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(cidLen))
	ptr += 8
	copy(data[ptr:ptr+ridLen], ridData)
	ptr += ridLen
	copy(data[ptr:ptr+sidLen], sidData)
	ptr += sidLen
	copy(data[ptr:ptr+cidLen], cidData)
	ptr += cidLen
	data[ptr] = marshBool(reply.Valid)
	ptr += 1

	return
}
func (reply *RotationReply) UnmarshalBinary(data []byte) (err error) {
	ptr := 0 // Used to index data

	// Read lengths
	ridLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8
	sidLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8
	cidLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8

	// Read RequestID
	if ridLen > 0 {
		err = reply.ReqID.UnmarshalBinary(data[ptr : ptr+ridLen])
		ptr += ridLen
		if err != nil {
			return
		}
	}

	// Read SessionID
	if sidLen > 0 {
		err = reply.SessionID.UnmarshalBinary(data[ptr : ptr+sidLen])
		ptr += sidLen
		if err != nil {
			return
		}
	}

	// Read CipherID
	if cidLen > 0 {
		err = reply.NewCipherID.UnmarshalBinary(data[ptr : ptr+cidLen])
		ptr += cidLen
		if err != nil {
			return
		}
	}

	// Read Valid
	reply.Valid = unmarshBool(data[ptr])
	ptr += 1

	return
}

// Encryption to shares

func (id *EncToSharesRequestID) MarshalBinary() ([]byte, error) {
	return (*uuid.UUID)(id).MarshalBinary()
}
func (id *EncToSharesRequestID) UnmarshalBinary(data []byte) error {
	return (*uuid.UUID)(id).UnmarshalBinary(data)
}

func (req *EncToSharesRequest) MarshalBinary() (data []byte, err error) {
	// Marshal RequestID
	ridData, err := req.ReqID.MarshalBinary()
	if err != nil {
		return
	}
	ridLen := len(ridData)

	// Marshal SessionID
	sidData, err := req.SessionID.MarshalBinary()
	if err != nil {
		return
	}
	sidLen := len(sidData)

	// Marshal CipherID
	cidData, err := req.CipherID.MarshalBinary()
	if err != nil {
		return
	}
	cidLen := len(cidData)

	// Build data as [<ridLen>, <sidLen>, <cidLen>, <RequestID>, <SessionID>, <CipherID>]
	data = make([]byte, 3*8+ridLen+sidLen+cidLen)
	ptr := 0 // Used to index data
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(ridLen))
	ptr += 8
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(sidLen))
	ptr += 8
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(cidLen))
	ptr += 8
	copy(data[ptr:ptr+ridLen], ridData)
	ptr += ridLen
	copy(data[ptr:ptr+sidLen], sidData)
	ptr += sidLen
	copy(data[ptr:ptr+cidLen], cidData)
	ptr += cidLen

	return
}
func (req *EncToSharesRequest) UnmarshalBinary(data []byte) (err error) {
	ptr := 0 // Used to index data

	// Read lengths
	ridLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8
	sidLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8
	cidLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8

	// Read RequestID
	if ridLen > 0 {
		err = req.ReqID.UnmarshalBinary(data[ptr : ptr+ridLen])
		ptr += ridLen
		if err != nil {
			return
		}
	}

	// Read SessionID
	if sidLen > 0 {
		err = req.SessionID.UnmarshalBinary(data[ptr : ptr+sidLen])
		ptr += sidLen
		if err != nil {
			return
		}
	}

	// Read CipherID
	if cidLen > 0 {
		err = req.CipherID.UnmarshalBinary(data[ptr : ptr+cidLen])
		ptr += cidLen
		if err != nil {
			return
		}
	}

	return
}

func (cfg *E2SConfig) MarshalBinary() (data []byte, err error) {
	// Marshal SessionID
	sidData, err := cfg.SessionID.MarshalBinary()
	if err != nil {
		return
	}
	sidLen := len(sidData)

	// Marshal SharesID
	shidData, err := cfg.SharesID.MarshalBinary()
	if err != nil {
		return
	}
	shidLen := len(shidData)

	// Marshal Ciphertext
	ctData, err := cfg.Ciphertext.MarshalBinary()
	if err != nil {
		return
	}
	ctLen := len(ctData)

	// Build data as [<sidLen>, <shidLen>, <ctLen>, <SessionID>, <CipherID>, <Ciphertext>]
	data = make([]byte, 8+8+8+sidLen+shidLen+ctLen)
	ptr := 0 // Used to index data
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(sidLen))
	ptr += 8
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(shidLen))
	ptr += 8
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(ctLen))
	ptr += 8
	copy(data[ptr:ptr+sidLen], sidData)
	ptr += sidLen
	copy(data[ptr:ptr+shidLen], shidData)
	ptr += shidLen
	copy(data[ptr:ptr+ctLen], ctData)
	ptr += ctLen

	return
}
func (cfg *E2SConfig) UnmarshalBinary(data []byte) (err error) {
	ptr := 0 // Used to index data

	// Read lengths
	sidLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8
	shidLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8
	ctLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8

	// Read SessionID
	if sidLen > 0 {
		err = cfg.SessionID.UnmarshalBinary(data[ptr : ptr+sidLen])
		ptr += sidLen
		if err != nil {
			return
		}
	}

	// Read SharesID
	if shidLen > 0 {
		err = cfg.SharesID.UnmarshalBinary(data[ptr : ptr+shidLen])
		ptr += shidLen
		if err != nil {
			return
		}
	}

	// Read Ciphertext
	if ctLen > 0 {
		if cfg.Ciphertext == nil {
			cfg.Ciphertext = &bfv.Ciphertext{}
		}
		err = cfg.Ciphertext.UnmarshalBinary(data[ptr : ptr+ctLen])
		ptr += ctLen
		if err != nil {
			return
		}
	}

	return
}

// Shares to encryption

func (id *SharesToEncRequestID) MarshalBinary() ([]byte, error) {
	return (*uuid.UUID)(id).MarshalBinary()
}
func (id *SharesToEncRequestID) UnmarshalBinary(data []byte) error {
	return (*uuid.UUID)(id).UnmarshalBinary(data)
}

func (cfg *S2EConfig) MarshalBinary() (data []byte, err error) {
	// Marshal SessionID
	sidData, err := cfg.SessionID.MarshalBinary()
	if err != nil {
		return
	}
	sidLen := len(sidData)

	// Marshal SharesID
	shidData, err := cfg.SharesID.MarshalBinary()
	if err != nil {
		return
	}
	shidLen := len(shidData)

	// Marshal Seed
	seedLen := len(cfg.Seed)

	// Build data as [<sidLen>, <shidLen>, <seedLen>, <SessionID>, <CipherID>, <Seed>]
	data = make([]byte, 3*8+sidLen+shidLen+seedLen)
	ptr := 0 // Used to index data
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(sidLen))
	ptr += 8
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(shidLen))
	ptr += 8
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(seedLen))
	ptr += 8
	copy(data[ptr:ptr+sidLen], sidData)
	ptr += sidLen
	copy(data[ptr:ptr+shidLen], shidData)
	ptr += shidLen
	copy(data[ptr:ptr+seedLen], cfg.Seed)
	ptr += seedLen

	return
}
func (cfg *S2EConfig) UnmarshalBinary(data []byte) (err error) {
	ptr := 0 // Used to index data

	// Read lengths
	sidLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8
	shidLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8
	seedLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8

	// Read SessionID
	if sidLen > 0 {
		err = cfg.SessionID.UnmarshalBinary(data[ptr : ptr+sidLen])
		ptr += sidLen
		if err != nil {
			return
		}
	}
	// Read SharesID
	if shidLen > 0 {
		err = cfg.SharesID.UnmarshalBinary(data[ptr : ptr+shidLen])
		ptr += shidLen
		if err != nil {
			return
		}
	}
	// Read Seed
	cfg.Seed = make([]byte, seedLen)
	copy(cfg.Seed, data[ptr:ptr+seedLen])
	ptr += seedLen

	return
}

func (reply *SharesToEncReply) MarshalBinary() (data []byte, err error) {
	// Marshal RequestID
	ridData, err := reply.ReqID.MarshalBinary()
	if err != nil {
		return
	}
	ridLen := len(ridData)

	// Marshal SessionID
	sidData, err := reply.SessionID.MarshalBinary()
	if err != nil {
		return
	}
	sidLen := len(sidData)

	// Marshal NewCipherID
	cidData := make([]byte, 0)
	cidData, err = reply.NewCipherID.MarshalBinary()
	if err != nil {
		return
	}
	cidLen := len(cidData)

	// Build data as [<ridLen>, <sidLen>, <cidLen>, <RequestID>, <SessionID>, <CipherID>, <Valid>]
	data = make([]byte, 3*8+ridLen+sidLen+cidLen+1)
	ptr := 0 // Used to index data
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(ridLen))
	ptr += 8
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(sidLen))
	ptr += 8
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(cidLen))
	ptr += 8
	copy(data[ptr:ptr+ridLen], ridData)
	ptr += ridLen
	copy(data[ptr:ptr+sidLen], sidData)
	ptr += sidLen
	copy(data[ptr:ptr+cidLen], cidData)
	ptr += cidLen
	data[ptr] = marshBool(reply.Valid)
	ptr += 1

	return
}
func (reply *SharesToEncReply) UnmarshalBinary(data []byte) (err error) {
	ptr := 0 // Used to index data

	// Read lengths
	ridLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8
	sidLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8
	cidLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8

	// Read RequestID
	if ridLen > 0 {
		err = reply.ReqID.UnmarshalBinary(data[ptr : ptr+ridLen])
		ptr += ridLen
		if err != nil {
			return
		}
	}

	// Read SessionID
	if sidLen > 0 {
		err = reply.SessionID.UnmarshalBinary(data[ptr : ptr+sidLen])
		ptr += sidLen
		if err != nil {
			return
		}
	}

	// Read CipherID
	if cidLen > 0 {
		err = reply.NewCipherID.UnmarshalBinary(data[ptr : ptr+cidLen])
		ptr += cidLen
		if err != nil {
			return
		}
	}

	// Read Valid
	reply.Valid = unmarshBool(data[ptr])
	ptr += 1

	return
}

// Create circuit

func (cfg *CreateCircuitConfig) MarshalBinary() (data []byte, err error) {
	// Marshal SessionID
	sidData, err := cfg.SessionID.MarshalBinary()
	if err != nil {
		return
	}
	sidLen := len(sidData)

	// Marshal CircuitID
	cidData, err := cfg.CircuitID.MarshalBinary()
	if err != nil {
		return
	}
	cidLen := len(cidData)

	// Marshal Description
	descData := []byte(cfg.Description)
	descLen := len(descData)

	// Build data as [<sidLen>, <cidLen>, <descLen>, <SessionID>, <CircuitID>, <Description>]
	data = make([]byte, 3*8+sidLen+cidLen+descLen)
	ptr := 0 // Used to index data
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(sidLen))
	ptr += 8
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(cidLen))
	ptr += 8
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(descLen))
	ptr += 8
	copy(data[ptr:ptr+sidLen], sidData)
	ptr += sidLen
	copy(data[ptr:ptr+cidLen], cidData)
	ptr += cidLen
	copy(data[ptr:ptr+descLen], descData)
	ptr += descLen

	return
}
func (cfg *CreateCircuitConfig) UnmarshalBinary(data []byte) (err error) {
	ptr := 0 // Used to index data

	// Read lengths
	sidLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8
	cidLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8
	descLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8

	// Read SessionID
	if sidLen > 0 {
		err = cfg.SessionID.UnmarshalBinary(data[ptr : ptr+sidLen])
		ptr += sidLen
		if err != nil {
			return
		}
	}

	// Read CircuitID
	if cidLen > 0 {
		err = cfg.CircuitID.UnmarshalBinary(data[ptr : ptr+cidLen])
		ptr += cidLen
		if err != nil {
			return
		}
	}

	// Read Description
	if descLen > 0 {
		cfg.Description = string(data[ptr : ptr+descLen])
		ptr += descLen
	}

	return
}

// Evaluate circuit

func (cfg *CloseCircuitConfig) MarshalBinary() ([]byte, error) {
	return cfg.CircuitID.MarshalBinary()
}
func (cfg *CloseCircuitConfig) UnmarshalBinary(data []byte) error {
	return cfg.CircuitID.UnmarshalBinary(data)
}

func (resp *EvalCircuitResponse) MarshalBinary() (data []byte, err error) {
	// Marshal Result
	cidData := make([]byte, 0)
	cidData, err = resp.Result.MarshalBinary()
	if err != nil {
		return
	}
	cidLen := len(cidData)

	// Build data as [<cidLen>, <CipherID>, <Valid>]
	data = make([]byte, 8+cidLen+1)
	ptr := 0 // Used to index data
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(cidLen))
	ptr += 8
	copy(data[ptr:ptr+cidLen], cidData)
	ptr += cidLen
	data[ptr] = marshBool(resp.Valid)
	ptr += 1

	return
}
func (resp *EvalCircuitResponse) UnmarshalBinary(data []byte) (err error) {
	ptr := 0 // Used to index data

	// Read lengths
	cidLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8

	// Read Result
	if cidLen > 0 {
		err = resp.Result.UnmarshalBinary(data[ptr : ptr+cidLen])
		ptr += cidLen
		if err != nil {
			return
		}
	}

	// Read Valid
	resp.Valid = unmarshBool(data[ptr])
	ptr += 1

	return
}

// Below are the marshallers that I wrote with so much toil. Please don't delete them, they can be a good reference

/*

func (req *CreateSessionRequest) MarshalBinary() (data []byte, err error) {
	// Marshal RequestID
	idData, err := marshUUID((uuid.UUID)(req.CreateSessionRequestID))
	if err != nil {
		return
	}
	idLen := len(idData)

	// Marshal CreateSessionQuery
	queryData := make([]byte, 0)
	if req.CreateSessionQuery != nil {
		queryData, err = req.CreateSessionQuery.MarshalBinary()
		if err != nil {
			return
		}
	}
	queryLen := len(queryData)

	// Build data as [<idLen>, <queryLen>, <RequestID>, <CreateSessionQuery>]
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


func (req *CreateSessionRequest) UnmarshalBinary(data []byte) (err error) {
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
		req.CreateSessionRequestID = (CreateSessionRequestID)(id)
		ptr += idLen
		if err != nil {
			return
		}
	}
	if queryLen > 0 {
		err = req.CreateSessionQuery.UnmarshalBinary(data[ptr : ptr+queryLen])
		ptr += queryLen
		if err != nil {
			return
		}
	}

	return
}

func (prep *CreateSessionBroadcast) MarshalBinary() (data []byte, err error) {
	data, err = (*CreateSessionRequest)(prep).MarshalBinary()

	return
}

func (prep *CreateSessionBroadcast) UnmarshalBinary(data []byte) (err error) {
	err = (*CreateSessionRequest)(prep).UnmarshalBinary(data)

	return
}

func (reply *CreateSessionReply) MarshalBinary() (data []byte, err error) {
	// Marshal RequestID
	idData, err := marshUUID((uuid.UUID)(reply.CreateSessionRequestID))
	if err != nil {
		return
	}
	idLen := len(idData)

	// Transform the rest to a Response, then marshal it
	resp := &CreateSessionResponse{reply.pubKeyGenerated, reply.evalKeyGenerated,
		reply.rotKeyGenerated}
	respData, _ := resp.MarshalBinary() // We know it won't return error
	// We know the length is 3

	// Build data as [<idLen>, <RequestID>, <CreateSessionResponse>]
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

func (reply *CreateSessionReply) UnmarshalBinary(data []byte) (err error) {
	ptr := 0 // Used to index data

	// Read length
	idLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8

	// Read fields
	if idLen > 0 {
		var id uuid.UUID
		id, err = unmarshUUID(data[ptr : ptr+idLen])
		reply.CreateSessionRequestID = (CreateSessionRequestID)(id)
		ptr += idLen
		if err != nil {
			return
		}
	}
	resp := &CreateSessionResponse{}
	_ = resp.UnmarshalBinary(data[ptr : ptr+3]) // We know it won't return error
	reply.pubKeyGenerated = resp.PubKeyGenerated
	reply.evalKeyGenerated = resp.EvalKeyGenerated
	reply.rotKeyGenerated = resp.RotKeyGenerated

	return
}

func (resp *CreateSessionResponse) MarshalBinary() (data []byte, err error) {
	// Directly build data as [<genPK>, <genEvK>, <genRtK>]
	data = make([]byte, 1+1+1)
	data[0] = marshBool(resp.PubKeyGenerated)
	data[1] = marshBool(resp.EvalKeyGenerated)
	data[2] = marshBool(resp.RotKeyGenerated)

	return
}

func (resp *CreateSessionResponse) UnmarshalBinary(data []byte) (err error) {
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
	data[2] = marshBool(query.rotationKey)
	data[3] = byte(query.RotIdx)

	return
}

func (query *KeyQuery) UnmarshalBinary(data []byte) (err error) {
	// Directly read fields
	query.PublicKey = unmarshBool(data[0])
	query.EvaluationKey = unmarshBool(data[1])
	query.rotationKey = unmarshBool(data[2])
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

	// Build data as [<idLen>, <RequestID>, <CreateSessionQuery>]
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
	}
	if queryLen > 0 {
		err = req.KeyQuery.UnmarshalBinary(data[ptr : ptr+queryLen])
		ptr += queryLen
		if err != nil {
			return
		}
	}

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
	}
	if pkLen > 0 {
		err = reply.pk.UnmarshalBinary(data[ptr : ptr+pkLen])
		ptr += pkLen
		if err != nil {
			return
		}
	}
	if evkLen > 0 {
		err = reply.evk.UnmarshalBinary(data[ptr : ptr+evkLen])
		ptr += evkLen
		if err != nil {
			return
		}
	}
	if rtkLen > 0 {
		err = reply.rtk.UnmarshalBinary(data[ptr : ptr+rtkLen])
		ptr += idLen
		if err != nil {
			return
		}
	}
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
	}
	if ctIdLen > 0 {
		var id uuid.UUID
		id, err = unmarshUUID(data[ptr : ptr+ctIdLen])
		reply.cipherID = (CipherID)(id)
		ptr += ctIdLen
		if err != nil {
			return
		}
	}

	return
}

func (resp *StoreAndNameResponse) MarshalBinary() (data []byte, err error) {
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

func (resp *StoreAndNameResponse) UnmarshalBinary(data []byte) (err error) {
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
	}

	return
}

// Retrieve





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
	}
	if pkLen > 0 {
		err = params.PublicKey.UnmarshalBinary(data[ptr : ptr+pkLen])
		ptr += pkLen
		if err != nil {
			return
		}
	}

	return
}

func (prep *RetrieveBroadcast) MarshalBinary() (data []byte, err error) {
	// Marshal RequestID
	idData, err := marshUUID((uuid.UUID)(prep.SwitchRequestID))
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
		prep.SwitchRequestID = (SwitchRequestID)(id)
		ptr += idLen
		if err != nil {
			return
		}
	}
	if paramsLen > 0 {
		err = prep.params.UnmarshalBinary(data[ptr : ptr+paramsLen])
		ptr += paramsLen
		if err != nil {
			return
		}
	}

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
	}
	if ctId2Len > 0 {
		var id uuid.UUID
		id, err = unmarshUUID(data[ptr : ptr+ctId2Len])
		query.CipherID2 = (CipherID)(id)
		ptr += ctId2Len
		if err != nil {
			return
		}
	}

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
	}
	if queryLen > 0 {
		err = req.SumQuery.UnmarshalBinary(data[ptr : ptr+queryLen])
		ptr += queryLen
		if err != nil {
			return
		}
	}

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
	}
	if respLen > 0 {
		resp := &SumResponse{}
		err = resp.UnmarshalBinary(data[ptr : ptr+respLen])
		ptr += respLen
		if err != nil {
			return
		}

		reply.newCipherID = resp.NewCipherID
		reply.valid = resp.Valid
	}

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
	}
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
	}
	if ctId2Len > 0 {
		var id uuid.UUID
		id, err = unmarshUUID(data[ptr : ptr+ctId2Len])
		query.CipherID2 = (CipherID)(id)
		ptr += ctId2Len
		if err != nil {
			return
		}
	}

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
	}
	if queryLen > 0 {
		err = req.MultiplyQuery.UnmarshalBinary(data[ptr : ptr+queryLen])
		ptr += queryLen
		if err != nil {
			return
		}
	}

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
	}
	if respLen > 0 {
		resp := &MultiplyResponse{}
		err = resp.UnmarshalBinary(data[ptr : ptr+respLen])
		ptr += respLen
		if err != nil {
			return
		}

		reply.newCipherID = resp.NewCipherID
		reply.valid = resp.Valid
	}

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
	}
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
	}

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
	}
	if queryLen > 0 {
		err = req.RelinQuery.UnmarshalBinary(data[ptr : ptr+queryLen])
		ptr += queryLen
		if err != nil {
			return
		}
	}

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
	}
	if respLen > 0 {
		resp := &RelinResponse{}
		err = resp.UnmarshalBinary(data[ptr : ptr+respLen])
		ptr += respLen
		if err != nil {
			return
		}

		reply.valid = resp.Valid
	}

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
	}

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
	}
	if queryLen > 0 {
		err = req.RefreshQuery.UnmarshalBinary(data[ptr : ptr+queryLen])
		ptr += queryLen
		if err != nil {
			return
		}
	}

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
	}
	if ctLen > 0 {
		err = prep.ct.UnmarshalBinary(data[ptr : ptr+ctLen])
		ptr += ctLen
		if err != nil {
			return
		}
	}

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
	}
	if respLen > 0 {
		resp := &RefreshResponse{}
		err = resp.UnmarshalBinary(data[ptr : ptr+respLen])
		ptr += respLen
		if err != nil {
			return
		}

		reply.valid = resp.Valid
	}

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
	}
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
	}
	if queryLen > 0 {
		err = req.RotationQuery.UnmarshalBinary(data[ptr : ptr+queryLen])
		ptr += queryLen
		if err != nil {
			return
		}
	}

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
	}
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
	}

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
	}
	if newIdLen > 0 {
		var id uuid.UUID
		id, err = unmarshUUID(data[ptr : ptr+newIdLen])
		resp.New = (CipherID)(id)
		ptr += newIdLen
		if err != nil {
			return
		}
	}
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
	}

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
	}
	if queryLen > 0 {
		err = req.EncToSharesQuery.UnmarshalBinary(data[ptr : ptr+queryLen])
		ptr += queryLen
		if err != nil {
			return
		}
	}

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
	}
	if ctLen > 0 {
		err = params.ct.UnmarshalBinary(data[ptr : ptr+ctLen])
		ptr += ctLen
		if err != nil {
			return
		}
	}

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
	}
	if paramsLen > 0 {
		err = prep.params.UnmarshalBinary(data[ptr : ptr+paramsLen])
		ptr += paramsLen
		if err != nil {
			return
		}
	}

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
	}
	if respLen > 0 {
		resp := &EncToSharesResponse{}
		err = resp.UnmarshalBinary(data[ptr : ptr+respLen])
		ptr += respLen
		if err != nil {
			return
		}

		reply.valid = resp.Valid
	}

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
	}

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
	}
	if queryLen > 0 {
		err = req.SharesToEncQuery.UnmarshalBinary(data[ptr : ptr+queryLen])
		ptr += queryLen
		if err != nil {
			return
		}
	}

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
	}

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
	}
	if paramsLen > 0 {
		err = prep.params.UnmarshalBinary(data[ptr : ptr+paramsLen])
		ptr += paramsLen
		if err != nil {
			return
		}
	}

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
	}
	if respLen > 0 {
		resp := &SharesToEncResponse{}
		err = resp.UnmarshalBinary(data[ptr : ptr+respLen])
		ptr += respLen
		if err != nil {
			return
		}

		reply.valid = resp.Valid
	}

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
