// This file defines the data structure for every message exchanged "directly" (i.e. except those exchanged,
// for example, by the protocols) by the service, both for client-server and server-root interaction.
// It also defines a data structure containing the MessageTypeID of all those messages.
// It also registers those message types to the underlying onet library, with the init method.

package service

import (
	"encoding/binary"
	"github.com/ldsec/lattigo/bfv"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
	uuid "gopkg.in/satori/go.uuid.v1"
	"lattigo-smc/protocols"
)

// MsgTypes contains the different message types.
type MsgTypes struct {
	msgCreateSessionQuery           network.MessageTypeID // Unused
	msgCreateSessionRequest         network.MessageTypeID
	msgCreateSessionBroadcast       network.MessageTypeID
	msgCreateSessionBroadcastAnswer network.MessageTypeID
	msgCreateSessionReply           network.MessageTypeID
	msgCreateSessionResponse        network.MessageTypeID // Unused

	msgCloseSessionQuery           network.MessageTypeID // Unused
	msgCloseSessionRequest         network.MessageTypeID
	msgCloseSessionBroadcast       network.MessageTypeID
	msgCloseSessionBroadcastAnswer network.MessageTypeID
	msgCloseSessionReply           network.MessageTypeID
	msgCloseSessionResponse        network.MessageTypeID // Unused

	msgGenPubKeyQuery    network.MessageTypeID // Unused
	msgGenPubKeyRequest  network.MessageTypeID
	msgGenPubKeyReply    network.MessageTypeID
	msgGenPubKeyResponse network.MessageTypeID // Unused

	msgGenEvalKeyQuery    network.MessageTypeID // Unused
	msgGenEvalKeyRequest  network.MessageTypeID
	msgGenEvalKeyReply    network.MessageTypeID
	msgGenEvalKeyResponse network.MessageTypeID // Unused

	msgGenRotKeyQuery    network.MessageTypeID // Unused
	msgGenRotKeyRequest  network.MessageTypeID
	msgGenRotKeyReply    network.MessageTypeID
	msgGenRotKeyResponse network.MessageTypeID // Unused

	msgKeyQuery    network.MessageTypeID // Unused
	msgKeyRequest  network.MessageTypeID
	msgKeyReply    network.MessageTypeID
	msgKeyResponse network.MessageTypeID // Unused

	msgStoreQuery    network.MessageTypeID // Unused
	msgStoreRequest  network.MessageTypeID
	msgStoreReply    network.MessageTypeID
	msgStoreResponse network.MessageTypeID // Unused

	msgRetrieveQuery   network.MessageTypeID // Unused
	msgRetrieveRequest network.MessageTypeID
	/*msgRetrieveBroadcast network.MessageTypeID*/
	msgRetrieveReply    network.MessageTypeID
	msgRetrieveResponse network.MessageTypeID // Unused

	msgSumQuery    network.MessageTypeID // Unused
	msgSumRequest  network.MessageTypeID
	msgSumReply    network.MessageTypeID
	msgSumResponse network.MessageTypeID // Unused

	msgMultiplyQuery    network.MessageTypeID // Unused
	msgMultiplyRequest  network.MessageTypeID
	msgMultiplyReply    network.MessageTypeID
	msgMultiplyResponse network.MessageTypeID // Unused

	msgRelinQuery    network.MessageTypeID // Unused
	msgRelinRequest  network.MessageTypeID
	msgRelinReply    network.MessageTypeID
	msgRelinResponse network.MessageTypeID // Unused

	msgRefreshQuery   network.MessageTypeID // Unused
	msgRefreshRequest network.MessageTypeID
	/*msgRefreshBroadcast network.MessageTypeID*/
	msgRefreshReply    network.MessageTypeID
	msgRefreshResponse network.MessageTypeID // Unused

	msgRotationQuery    network.MessageTypeID // Unused
	msgRotationRequest  network.MessageTypeID
	msgRotationReply    network.MessageTypeID
	msgRotationResponse network.MessageTypeID // Unused

	msgEncToSharesQuery   network.MessageTypeID // Unused
	msgEncToSharesRequest network.MessageTypeID
	/*msgEncToSharesBroadcast network.MessageTypeID*/
	msgEncToSharesReply    network.MessageTypeID
	msgEncToSharesResponse network.MessageTypeID // Unused

	msgSharesToEncQuery   network.MessageTypeID // Unused
	msgSharesToEncRequest network.MessageTypeID
	/*msgSharesToEncBroadcast network.MessageTypeID*/
	msgSharesToEncReply    network.MessageTypeID
	msgSharesToEncResponse network.MessageTypeID // Unused
}

var msgTypes = MsgTypes{}

// Registers all the message types to the onet library
func init() {
	log.Lvl1("Registering messages")

	msgTypes.msgCreateSessionQuery = network.RegisterMessage(&CreateSessionQuery{}) // Unused
	msgTypes.msgCreateSessionRequest = network.RegisterMessage(&CreateSessionRequest{})
	msgTypes.msgCreateSessionBroadcast = network.RegisterMessage(&CreateSessionBroadcast{})
	msgTypes.msgCreateSessionBroadcast = network.RegisterMessage(&CreateSessionBroadcastAnswer{})
	msgTypes.msgCreateSessionReply = network.RegisterMessage(&CreateSessionReply{})
	msgTypes.msgCreateSessionResponse = network.RegisterMessage(&CreateSessionResponse{}) // Unused

	msgTypes.msgCloseSessionQuery = network.RegisterMessage(&CloseSessionQuery{}) // Unused
	msgTypes.msgCloseSessionRequest = network.RegisterMessage(&CloseSessionRequest{})
	msgTypes.msgCloseSessionBroadcast = network.RegisterMessage(&CloseSessionBroadcast{})
	msgTypes.msgCloseSessionBroadcast = network.RegisterMessage(&CloseSessionBroadcastAnswer{})
	msgTypes.msgCloseSessionReply = network.RegisterMessage(&CloseSessionReply{})
	msgTypes.msgCloseSessionResponse = network.RegisterMessage(&CloseSessionResponse{}) // Unused

	msgTypes.msgGenPubKeyQuery = network.RegisterMessage(&GenPubKeyQuery{}) // Unused
	msgTypes.msgGenPubKeyRequest = network.RegisterMessage(&GenPubKeyRequest{})
	msgTypes.msgGenPubKeyReply = network.RegisterMessage(&GenPubKeyReply{})
	msgTypes.msgGenPubKeyResponse = network.RegisterMessage(&GenPubKeyResponse{}) // Unused

	msgTypes.msgGenEvalKeyQuery = network.RegisterMessage(&GenEvalKeyQuery{}) // Unused
	msgTypes.msgGenEvalKeyRequest = network.RegisterMessage(&GenEvalKeyRequest{})
	msgTypes.msgGenEvalKeyReply = network.RegisterMessage(&GenEvalKeyReply{})
	msgTypes.msgGenEvalKeyResponse = network.RegisterMessage(&GenEvalKeyResponse{}) // Unused

	msgTypes.msgKeyQuery = network.RegisterMessage(&KeyQuery{}) // Unused
	msgTypes.msgKeyRequest = network.RegisterMessage(&KeyRequest{})
	msgTypes.msgKeyReply = network.RegisterMessage(&KeyReply{})
	msgTypes.msgKeyResponse = network.RegisterMessage(&KeyResponse{}) // Unused

	msgTypes.msgStoreQuery = network.RegisterMessage(&StoreQuery{}) // Unused
	msgTypes.msgStoreRequest = network.RegisterMessage(&StoreRequest{})
	msgTypes.msgStoreReply = network.RegisterMessage(&StoreReply{})
	msgTypes.msgStoreResponse = network.RegisterMessage(&StoreResponse{}) // Unused

	msgTypes.msgRetrieveQuery = network.RegisterMessage(&RetrieveQuery{}) // Unused
	msgTypes.msgRetrieveRequest = network.RegisterMessage(&RetrieveRequest{})
	/*msgTypes.msgRetrieveBroadcast = network.RegisterMessage(&RetrieveBroadcast{})*/
	msgTypes.msgRetrieveReply = network.RegisterMessage(&RetrieveReply{})
	msgTypes.msgRetrieveResponse = network.RegisterMessage(&RetrieveResponse{}) // Unused

	msgTypes.msgSumQuery = network.RegisterMessage(&SumQuery{}) // Unused
	msgTypes.msgSumRequest = network.RegisterMessage(&SumRequest{})
	msgTypes.msgSumReply = network.RegisterMessage(&SumReply{})
	msgTypes.msgSumResponse = network.RegisterMessage(&SumResponse{}) // Unused

	msgTypes.msgMultiplyQuery = network.RegisterMessage(&MultiplyQuery{}) // Unused
	msgTypes.msgMultiplyRequest = network.RegisterMessage(&MultiplyRequest{})
	msgTypes.msgMultiplyReply = network.RegisterMessage(&MultiplyReply{})
	msgTypes.msgMultiplyResponse = network.RegisterMessage(&MultiplyResponse{}) // Unused

	msgTypes.msgRelinQuery = network.RegisterMessage(&RelinQuery{}) // Unused
	msgTypes.msgRelinRequest = network.RegisterMessage(&RelinRequest{})
	msgTypes.msgRelinReply = network.RegisterMessage(&RelinReply{})
	msgTypes.msgRelinResponse = network.RegisterMessage(&RelinResponse{}) // Unused

	msgTypes.msgRefreshQuery = network.RegisterMessage(&RefreshQuery{}) // Unused
	msgTypes.msgRefreshRequest = network.RegisterMessage(&RefreshRequest{})
	/*msgTypes.msgRefreshBroadcast = network.RegisterMessage(&RefreshBroadcast{})*/
	msgTypes.msgRefreshReply = network.RegisterMessage(&RefreshReply{})
	msgTypes.msgRefreshResponse = network.RegisterMessage(&RefreshResponse{}) // Unused

	msgTypes.msgRotationQuery = network.RegisterMessage(&RotationQuery{}) // Unused
	msgTypes.msgRotationRequest = network.RegisterMessage(&RotationRequest{})
	msgTypes.msgRotationReply = network.RegisterMessage(&RotationReply{})
	msgTypes.msgRotationResponse = network.RegisterMessage(&RotationResponse{}) // Unused

	msgTypes.msgEncToSharesQuery = network.RegisterMessage(&EncToSharesQuery{}) // Unused
	msgTypes.msgEncToSharesRequest = network.RegisterMessage(&EncToSharesRequest{})
	/*msgTypes.msgEncToSharesBroadcast = network.RegisterMessage(&EncToSharesBroadcast{})*/
	msgTypes.msgEncToSharesReply = network.RegisterMessage(&EncToSharesReply{})
	msgTypes.msgEncToSharesResponse = network.RegisterMessage(&EncToSharesResponse{}) // Unused

	msgTypes.msgSharesToEncQuery = network.RegisterMessage(&SharesToEncQuery{}) // Unused
	msgTypes.msgSharesToEncRequest = network.RegisterMessage(&SharesToEncRequest{})
	/*msgTypes.msgSharesToEncBroadcast = network.RegisterMessage(&SharesToEncBroadcast{})*/
	msgTypes.msgSharesToEncReply = network.RegisterMessage(&SharesToEncReply{})
	msgTypes.msgSharesToEncResponse = network.RegisterMessage(&SharesToEncResponse{}) // Unused

	_ = network.RegisterMessage(&protocols.Start{}) // TODO: necessary?
}

/*********************** Message structs *********************/

// SessionID

type SessionID uuid.UUID

var NilSessionID = SessionID(uuid.Nil)

func newSessionID() SessionID {
	return SessionID(uuid.NewV1())
}
func (id *SessionID) MarshalBinary() ([]byte, error) {
	return (*uuid.UUID)(id).MarshalBinary()
}
func (id *SessionID) UnmarshalBinary(data []byte) error {
	return (*uuid.UUID)(id).UnmarshalBinary(data)
}
func (id SessionID) String() string {
	return (uuid.UUID)(id).String()
}

// CipherID

type CipherID uuid.UUID

var NilCipherID = CipherID(uuid.Nil)

func newCipherID() CipherID {
	return CipherID(uuid.NewV1())
}
func (id *CipherID) MarshalBinary() ([]byte, error) {
	return (*uuid.UUID)(id).MarshalBinary()
}
func (id *CipherID) UnmarshalBinary(data []byte) error {
	return (*uuid.UUID)(id).UnmarshalBinary(data)
}
func (id CipherID) String() string {
	return (uuid.UUID)(id).String()
}

// Create Session

type CreateSessionQuery struct {
	Roster *onet.Roster
	Params *bfv.Parameters
	Seed   []byte
}

type CreateSessionRequestID uuid.UUID

func newCreateSessionRequestID() CreateSessionRequestID {
	return CreateSessionRequestID(uuid.NewV1())
}
func (id *CreateSessionRequestID) MarshalBinary() ([]byte, error) {
	return (*uuid.UUID)(id).MarshalBinary()
}
func (id *CreateSessionRequestID) UnmarshalBinary(data []byte) error {
	return (*uuid.UUID)(id).UnmarshalBinary(data)
}
func (id CreateSessionRequestID) String() string {
	return (uuid.UUID)(id).String()
}

type CreateSessionRequest struct {
	ReqID CreateSessionRequestID
	Query *CreateSessionQuery
}

type CreateSessionBroadcast struct {
	ReqID CreateSessionRequestID

	SessionID SessionID
	Query     *CreateSessionQuery
}

type CreateSessionBroadcastAnswer struct {
	ReqID CreateSessionRequestID
	Valid bool
}

type CreateSessionReply struct {
	ReqID CreateSessionRequestID

	SessionID SessionID
	Valid     bool
}

type CreateSessionResponse struct {
	SessionID SessionID
	Valid     bool
}

// Close Session

type CloseSessionQuery struct {
	SessionID SessionID
}

type CloseSessionRequestID uuid.UUID

func newCloseSessionRequestID() CloseSessionRequestID {
	return CloseSessionRequestID(uuid.NewV1())
}
func (id *CloseSessionRequestID) MarshalBinary() ([]byte, error) {
	return (*uuid.UUID)(id).MarshalBinary()
}
func (id *CloseSessionRequestID) UnmarshalBinary(data []byte) error {
	return (*uuid.UUID)(id).UnmarshalBinary(data)
}
func (id CloseSessionRequestID) String() string {
	return (uuid.UUID)(id).String()
}

type CloseSessionRequest struct {
	ReqID     CloseSessionRequestID
	SessionID SessionID
	Query     *CloseSessionQuery
}

type CloseSessionBroadcast struct {
	ReqID CloseSessionRequestID

	Query *CloseSessionQuery
}

type CloseSessionBroadcastAnswer struct {
	ReqID CloseSessionRequestID
	Valid bool
}

type CloseSessionReply struct {
	ReqID CloseSessionRequestID

	Valid bool
}

type CloseSessionResponse struct {
	Valid bool
}

// Generate Public Key

type GenPubKeyQuery struct {
	SessionID SessionID
}

type GenPubKeyRequestID uuid.UUID

func newGenPubKeyRequestID() GenPubKeyRequestID {
	return GenPubKeyRequestID(uuid.NewV1())
}
func (id *GenPubKeyRequestID) MarshalBinary() ([]byte, error) {
	return (*uuid.UUID)(id).MarshalBinary()
}
func (id *GenPubKeyRequestID) UnmarshalBinary(data []byte) error {
	return (*uuid.UUID)(id).UnmarshalBinary(data)
}
func (id GenPubKeyRequestID) String() string {
	return (uuid.UUID)(id).String()
}

type GenPubKeyRequest struct {
	SessionID SessionID
	ReqID     GenPubKeyRequestID
	Query     *GenPubKeyQuery
}

type GenPubKeyConfig struct {
	SessionID SessionID
}

func (cfg *GenPubKeyConfig) MarshalBinary() (data []byte, err error) {
	// Marshal SessionID
	sidData, err := cfg.SessionID.MarshalBinary()
	if err != nil {
		return
	}
	sidLen := len(sidData)

	// Build data as [<sidLen>, <SessionID>]
	data = make([]byte, 8+sidLen)
	ptr := 0 // Used to index data
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(sidLen))
	ptr += 8
	copy(data[ptr:ptr+sidLen], sidData)
	ptr += sidLen

	return
}
func (cfg *GenPubKeyConfig) UnmarshalBinary(data []byte) (err error) {
	ptr := 0 // Used to index data

	// Read lengths
	sidLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8

	// Read fields
	if sidLen > 0 {
		err := cfg.SessionID.UnmarshalBinary(data[ptr : ptr+sidLen])
		ptr += sidLen
		if err != nil {
			return
		}
	}

	return
}

/*
type CreateSessionBroadcast struct {
	ReqID CreateSessionRequestID

	SessionID SessionID
	Query *CreateSessionQuery
}
*/

type GenPubKeyReply struct {
	SessionID SessionID
	ReqID     GenPubKeyRequestID

	MasterPublicKey *bfv.PublicKey
	Valid           bool
}

type GenPubKeyResponse struct {
	MasterPublicKey *bfv.PublicKey
	Valid           bool
}

// Generate Evaluation Key

type GenEvalKeyQuery struct {
	SessionID SessionID
}

type GenEvalKeyRequestID uuid.UUID

func newGenEvalKeyRequestID() GenEvalKeyRequestID {
	return GenEvalKeyRequestID(uuid.NewV1())
}
func (id *GenEvalKeyRequestID) MarshalBinary() ([]byte, error) {
	return (*uuid.UUID)(id).MarshalBinary()
}
func (id *GenEvalKeyRequestID) UnmarshalBinary(data []byte) error {
	return (*uuid.UUID)(id).UnmarshalBinary(data)
}
func (id GenEvalKeyRequestID) String() string {
	return (uuid.UUID)(id).String()
}

type GenEvalKeyRequest struct {
	SessionID SessionID
	ReqID     GenEvalKeyRequestID
	Query     *GenEvalKeyQuery
}

type GenEvalKeyConfig struct {
	SessionID SessionID
}

func (cfg *GenEvalKeyConfig) MarshalBinary() (data []byte, err error) {
	// Marshal SessionID
	sidData, err := cfg.SessionID.MarshalBinary()
	if err != nil {
		return
	}
	sidLen := len(sidData)

	// Build data as [<sidLen>, <SessionID>]
	data = make([]byte, 8+sidLen)
	ptr := 0 // Used to index data
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(sidLen))
	ptr += 8
	copy(data[ptr:ptr+sidLen], sidData)
	ptr += sidLen

	return
}
func (cfg *GenEvalKeyConfig) UnmarshalBinary(data []byte) (err error) {
	ptr := 0 // Used to index data

	// Read lengths
	sidLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8

	// Read fields
	if sidLen > 0 {
		err := cfg.SessionID.UnmarshalBinary(data[ptr : ptr+sidLen])
		ptr += sidLen
		if err != nil {
			return
		}
	}

	return
}

/*
type CreateSessionBroadcast struct {
	ReqID CreateSessionRequestID

	SessionID SessionID
	Query *CreateSessionQuery
}
*/

type GenEvalKeyReply struct {
	SessionID SessionID
	ReqID     GenEvalKeyRequestID

	Valid bool
}

type GenEvalKeyResponse struct {
	Valid bool
}

// Generate Rotation Key

type GenRotKeyQuery struct {
	SessionID SessionID
	RotIdx    int
	K         uint64
}

type GenRotKeyRequestID uuid.UUID

func newGenRotKeyRequestID() GenRotKeyRequestID {
	return GenRotKeyRequestID(uuid.NewV1())
}
func (id *GenRotKeyRequestID) MarshalBinary() ([]byte, error) {
	return (*uuid.UUID)(id).MarshalBinary()
}
func (id *GenRotKeyRequestID) UnmarshalBinary(data []byte) error {
	return (*uuid.UUID)(id).UnmarshalBinary(data)
}
func (id GenRotKeyRequestID) String() string {
	return (uuid.UUID)(id).String()
}

type GenRotKeyRequest struct {
	SessionID SessionID
	ReqID     GenRotKeyRequestID
	Query     *GenRotKeyQuery
}

type GenRotKeyConfig struct {
	SessionID SessionID

	RotIdx int
	K      uint64
}

func (cfg *GenRotKeyConfig) MarshalBinary() (data []byte, err error) {
	// Marshal SessionID
	sidData, err := cfg.SessionID.MarshalBinary()
	if err != nil {
		return
	}
	sidLen := len(sidData)

	// Build data as [<sidLen>, <SessionID>, <RotIdx>, <K>]
	data = make([]byte, 8+sidLen+8+8)
	ptr := 0 // Used to index data
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(sidLen))
	ptr += 8
	copy(data[ptr:ptr+sidLen], sidData)
	ptr += sidLen
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(cfg.RotIdx))
	ptr += 8
	binary.BigEndian.PutUint64(data[ptr:ptr+8], cfg.K)
	ptr += 8

	return
}
func (cfg *GenRotKeyConfig) UnmarshalBinary(data []byte) (err error) {
	ptr := 0 // Used to index data

	// Read lengths
	sidLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8

	// Read fields
	if sidLen > 0 {
		err := cfg.SessionID.UnmarshalBinary(data[ptr : ptr+sidLen])
		ptr += sidLen
		if err != nil {
			return
		}
	}
	cfg.RotIdx = int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8
	cfg.K = binary.BigEndian.Uint64(data[ptr : ptr+8])
	ptr += 8

	return
}

/*
type CreateSessionBroadcast struct {
	ReqID CreateSessionRequestID

	SessionID SessionID
	Query *CreateSessionQuery
}
*/

type GenRotKeyReply struct {
	SessionID SessionID
	ReqID     GenRotKeyRequestID

	Valid bool
}

type GenRotKeyResponse struct {
	Valid bool
}

// Key

type KeyQuery struct {
	SessionID SessionID

	PublicKey     bool
	EvaluationKey bool
	RotationKey   bool
	RotIdx        int
}

type KeyRequestID uuid.UUID

func newKeyRequestID() KeyRequestID {
	return KeyRequestID(uuid.NewV1())
}
func (id *KeyRequestID) MarshalBinary() ([]byte, error) {
	return (*uuid.UUID)(id).MarshalBinary()
}
func (id *KeyRequestID) UnmarshalBinary(data []byte) error {
	return (*uuid.UUID)(id).UnmarshalBinary(data)
}
func (id KeyRequestID) String() string {
	return (uuid.UUID)(id).String()
}

type KeyRequest struct {
	SessionID SessionID

	ReqID KeyRequestID
	Query *KeyQuery
}

// KeyReply is sent by root to server, in response to KeyQuery.
// Contains the requested keys, if they exist.
type KeyReply struct {
	SessionID SessionID

	ReqID KeyRequestID

	PublicKey *bfv.PublicKey
	EvalKey   *bfv.EvaluationKey
	RotKeys   *bfv.RotationKeys
	RotIdx    int

	Valid bool
}

type KeyResponse struct {
	SessionID SessionID

	PubKeyObtained  bool
	EvalKeyObtained bool
	RotKeyObtained  bool

	Valid bool
}

// Store

// StoreQuery contains the data to store.
type StoreQuery struct {
	SessionID SessionID

	Ciphertext *bfv.Ciphertext
}

type StoreRequestID uuid.UUID

func newStoreRequestID() StoreRequestID {
	return StoreRequestID(uuid.NewV1())
}
func (id *StoreRequestID) MarshalBinary() ([]byte, error) {
	return (*uuid.UUID)(id).MarshalBinary()
}
func (id *StoreRequestID) UnmarshalBinary(data []byte) error {
	return (*uuid.UUID)(id).UnmarshalBinary(data)
}
func (id StoreRequestID) String() string {
	return (uuid.UUID)(id).String()
}

// StoreRequest is sent by server to root.
// Contains new ciphertext to store.
type StoreRequest struct {
	SessionID SessionID

	ReqID StoreRequestID
	Query *StoreQuery
}

type StoreReply struct {
	SessionID SessionID

	ReqID StoreRequestID

	CipherID CipherID
	Valid    bool
}

type StoreResponse struct {
	CipherID CipherID
	Valid    bool
}

// Retrieve

//RetrieveQuery query for a ciphertext represented by ID to be switched under PublicKey
type RetrieveQuery struct {
	SessionID SessionID

	PublicKey *bfv.PublicKey
	CipherID  CipherID
}

type RetrieveRequestID uuid.UUID

func newRetrieveRequestID() RetrieveRequestID {
	return RetrieveRequestID(uuid.NewV1())
}
func (id *RetrieveRequestID) MarshalBinary() ([]byte, error) {
	return (*uuid.UUID)(id).MarshalBinary()
}
func (id *RetrieveRequestID) UnmarshalBinary(data []byte) error {
	return (*uuid.UUID)(id).UnmarshalBinary(data)
}
func (id RetrieveRequestID) String() string {
	return (uuid.UUID)(id).String()
}

type RetrieveRequest struct {
	SessionID SessionID

	ReqID RetrieveRequestID
	Query *RetrieveQuery
}

type PublicSwitchConfig struct {
	SessionID  SessionID
	PublicKey  *bfv.PublicKey
	Ciphertext *bfv.Ciphertext
}

func (cfg *PublicSwitchConfig) MarshalBinary() (data []byte, err error) {
	// Marshal SessionID
	sidData, err := cfg.SessionID.MarshalBinary()
	if err != nil {
		return
	}
	sidLen := len(sidData)

	// Marshal CipherID
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
func (cfg *PublicSwitchConfig) UnmarshalBinary(data []byte) (err error) {
	ptr := 0 // Used to index data

	// Read lengths
	sidLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8
	pkLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8
	ctLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8

	// Read fields
	if sidLen > 0 {
		err := cfg.SessionID.UnmarshalBinary(data[ptr : ptr+sidLen])
		ptr += sidLen
		if err != nil {
			return
		}
	}
	if pkLen > 0 {
		err := cfg.PublicKey.UnmarshalBinary(data[ptr : ptr+pkLen])
		ptr += pkLen
		if err != nil {
			return
		}
	}
	if ctLen > 0 {
		err := cfg.Ciphertext.UnmarshalBinary(data[ptr : ptr+ctLen])
		ptr += ctLen
		if err != nil {
			return
		}
	}

	return
}

/*
type RetrieveBroadcast struct {
	SessionID SessionID

	ReqID  RetrieveRequestID
	Params *SwitchingParameters
}
*/

//RetrieveReply contains the ciphertext switched under the key requested.
type RetrieveReply struct {
	SessionID SessionID

	ReqID RetrieveRequestID

	Ciphertext *bfv.Ciphertext
	Valid      bool
}

type RetrieveResponse struct {
	Ciphertext *bfv.Ciphertext
	Valid      bool
}

// Sum

// Client asks to sum ciphertexts ID1 and ID2.
type SumQuery struct {
	SessionID SessionID

	CipherID1 CipherID
	CipherID2 CipherID
}

// Server further assigns an ID to the query
type SumRequestID uuid.UUID

func newSumRequestID() SumRequestID {
	return SumRequestID(uuid.NewV1())
}
func (id *SumRequestID) MarshalBinary() ([]byte, error) {
	return (*uuid.UUID)(id).MarshalBinary()
}
func (id *SumRequestID) UnmarshalBinary(data []byte) error {
	return (*uuid.UUID)(id).UnmarshalBinary(data)
}
func (id SumRequestID) String() string {
	return (uuid.UUID)(id).String()
}

// Message sent by server to root.
type SumRequest struct {
	SessionID SessionID

	ReqID SumRequestID
	Query *SumQuery
}

// Root answers with the same SumRequestID, the CipherID of the new ciphertext,
// and a flag indicating whether the operation succeeded.
type SumReply struct {
	SessionID SessionID

	ReqID SumRequestID

	NewCipherID CipherID
	Valid       bool
}

type SumResponse struct {
	NewCipherID CipherID
	Valid       bool
}

// Multiply

// Client asks to multiply ID1 and ID2
type MultiplyQuery struct {
	SessionID SessionID

	CipherID1 CipherID
	CipherID2 CipherID
}

type MultiplyRequestID uuid.UUID

func newMultiplyRequestID() MultiplyRequestID {
	return MultiplyRequestID(uuid.NewV1())
}
func (id *MultiplyRequestID) MarshalBinary() ([]byte, error) {
	return (*uuid.UUID)(id).MarshalBinary()
}
func (id *MultiplyRequestID) UnmarshalBinary(data []byte) error {
	return (*uuid.UUID)(id).UnmarshalBinary(data)
}
func (id MultiplyRequestID) String() string {
	return (uuid.UUID)(id).String()
}

// Message sent by server to root.
type MultiplyRequest struct {
	SessionID SessionID

	ReqID MultiplyRequestID
	Query *MultiplyQuery
}

// Root answers with the same SumRequestID, the CipherID of the new ciphertext,
// and a flag indicating whether the operation succeeded.
type MultiplyReply struct {
	SessionID SessionID

	ReqID       MultiplyRequestID
	NewCipherID CipherID
	Valid       bool
}

type MultiplyResponse struct {
	NewCipherID CipherID
	Valid       bool
}

// Relinearise

// Client asks to relinearise the given CipherID
type RelinQuery struct {
	SessionID SessionID

	CipherID CipherID
}

type RelinRequestID uuid.UUID

func newRelinRequestID() RelinRequestID {
	return RelinRequestID(uuid.NewV1())
}
func (id *RelinRequestID) MarshalBinary() ([]byte, error) {
	return (*uuid.UUID)(id).MarshalBinary()
}
func (id *RelinRequestID) UnmarshalBinary(data []byte) error {
	return (*uuid.UUID)(id).UnmarshalBinary(data)
}
func (id RelinRequestID) String() string {
	return (uuid.UUID)(id).String()
}

type RelinRequest struct {
	SessionID SessionID

	ReqID RelinRequestID
	Query *RelinQuery
}

type RelinReply struct {
	SessionID SessionID

	ReqID RelinRequestID
	Valid bool
}

type RelinResponse struct {
	Valid bool
}

// Refresh

//RefreshQuery query for ID1 to be refreshed.
type RefreshQuery struct {
	SessionID SessionID

	CipherID CipherID
}

type RefreshRequestID uuid.UUID

func newRefreshRequestID() RefreshRequestID {
	return RefreshRequestID(uuid.NewV1())
}
func (id *RefreshRequestID) MarshalBinary() ([]byte, error) {
	return (*uuid.UUID)(id).MarshalBinary()
}
func (id *RefreshRequestID) UnmarshalBinary(data []byte) error {
	return (*uuid.UUID)(id).UnmarshalBinary(data)
}
func (id RefreshRequestID) String() string {
	return (uuid.UUID)(id).String()
}

type RefreshRequest struct {
	SessionID SessionID

	ReqID RefreshRequestID
	Query *RefreshQuery
}

type RefreshConfig struct {
	SessionID  SessionID
	Ciphertext *bfv.Ciphertext
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

	// Build data as [<sidLen>, <cidLen>, <ctLen>, <SessionID>, <CipherID>, <Ciphertext>]
	data = make([]byte, 8+8+sidLen+ctLen)
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
func (cfg *RefreshConfig) UnmarshalBinary(data []byte) (err error) {
	ptr := 0 // Used to index data

	// Read lengths
	sidLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8
	ctLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8

	// Read fields
	if sidLen > 0 {
		err := cfg.SessionID.UnmarshalBinary(data[ptr : ptr+sidLen])
		ptr += sidLen
		if err != nil {
			return
		}
	}
	if ctLen > 0 {
		err := cfg.Ciphertext.UnmarshalBinary(data[ptr : ptr+ctLen])
		ptr += ctLen
		if err != nil {
			return
		}
	}

	return
}

/*
type RefreshBroadcast struct {
	ReqID      RefreshRequestID
	Ciphertext *bfv.Ciphertext
}
*/

type RefreshReply struct {
	SessionID SessionID

	ReqID RefreshRequestID

	Valid bool
}

type RefreshResponse struct {
	Valid bool
}

// Rotation

type RotationQuery struct {
	SessionID SessionID

	CipherID CipherID
	K        uint64
	RotIdx   int
}

type RotationRequestID uuid.UUID

func newRotationRequestID() RotationRequestID {
	return RotationRequestID(uuid.NewV1())
}
func (id *RotationRequestID) MarshalBinary() ([]byte, error) {
	return (*uuid.UUID)(id).MarshalBinary()
}
func (id *RotationRequestID) UnmarshalBinary(data []byte) error {
	return (*uuid.UUID)(id).UnmarshalBinary(data)
}
func (id RotationRequestID) String() string {
	return (uuid.UUID)(id).String()
}

type RotationRequest struct {
	SessionID SessionID

	ReqID RotationRequestID
	Query *RotationQuery
}

type RotationReply struct {
	SessionID SessionID

	ReqID RotationRequestID

	NewCipherID CipherID
	Valid       bool
}

type RotationResponse struct {
	NewCipherID CipherID
	Valid       bool
}

// Encryption to shares

type EncToSharesQuery struct {
	SessionID SessionID

	CipherID CipherID
}

type EncToSharesRequestID uuid.UUID

func newEncToSharesRequestID() EncToSharesRequestID {
	return EncToSharesRequestID(uuid.NewV1())
}
func (id *EncToSharesRequestID) MarshalBinary() ([]byte, error) {
	return (*uuid.UUID)(id).MarshalBinary()
}
func (id *EncToSharesRequestID) UnmarshalBinary(data []byte) error {
	return (*uuid.UUID)(id).UnmarshalBinary(data)
}
func (id EncToSharesRequestID) String() string {
	return (uuid.UUID)(id).String()
}

type EncToSharesRequest struct {
	SessionID SessionID

	ReqID EncToSharesRequestID
	Query *EncToSharesQuery
}

type E2SConfig struct {
	SessionID  SessionID
	CipherID   CipherID
	Ciphertext *bfv.Ciphertext
}

func (cfg *E2SConfig) MarshalBinary() (data []byte, err error) {
	// Marshal SessionID
	sidData, err := cfg.SessionID.MarshalBinary()
	if err != nil {
		return
	}
	sidLen := len(sidData)

	// Marshal CipherID
	cidData, err := cfg.CipherID.MarshalBinary()
	if err != nil {
		return
	}
	cidLen := len(cidData)

	// Marshal Ciphertext
	ctData, err := cfg.Ciphertext.MarshalBinary()
	if err != nil {
		return
	}
	ctLen := len(ctData)

	// Build data as [<sidLen>, <cidLen>, <ctLen>, <SessionID>, <CipherID>, <Ciphertext>]
	data = make([]byte, 8+8+8+sidLen+cidLen+ctLen)
	ptr := 0 // Used to index data
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(sidLen))
	ptr += 8
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(cidLen))
	ptr += 8
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(ctLen))
	ptr += 8
	copy(data[ptr:ptr+sidLen], sidData)
	ptr += sidLen
	copy(data[ptr:ptr+cidLen], cidData)
	ptr += cidLen
	copy(data[ptr:ptr+ctLen], ctData)
	ptr += ctLen

	return
}
func (cfg *E2SConfig) UnmarshalBinary(data []byte) (err error) {
	ptr := 0 // Used to index data

	// Read lengths
	sidLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8
	cidLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8
	ctLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8

	// Read fields
	if sidLen > 0 {
		err := cfg.SessionID.UnmarshalBinary(data[ptr : ptr+sidLen])
		ptr += sidLen
		if err != nil {
			return
		}
	}
	if cidLen > 0 {
		err := cfg.CipherID.UnmarshalBinary(data[ptr : ptr+cidLen])
		ptr += cidLen
		if err != nil {
			return
		}
	}
	if ctLen > 0 {
		err := cfg.Ciphertext.UnmarshalBinary(data[ptr : ptr+ctLen])
		ptr += ctLen
		if err != nil {
			return
		}
	}

	return
}

/*
type EncToSharesBroadcast struct {
	SessionID SessionID

	ReqID EncToSharesRequestID

	Params *E2SParameters
}
*/

type EncToSharesReply struct {
	SessionID SessionID

	ReqID EncToSharesRequestID
	// The CipherID will be the same
	Valid bool
}

type EncToSharesResponse struct {
	Valid bool
}

// Shares to encryption

type SharesToEncQuery struct {
	SessionID SessionID

	CipherID CipherID
}

type SharesToEncRequestID uuid.UUID

func newSharesToEncRequestID() SharesToEncRequestID {
	return SharesToEncRequestID(uuid.NewV1())
}
func (id *SharesToEncRequestID) MarshalBinary() ([]byte, error) {
	return (*uuid.UUID)(id).MarshalBinary()
}
func (id *SharesToEncRequestID) UnmarshalBinary(data []byte) error {
	return (*uuid.UUID)(id).UnmarshalBinary(data)
}
func (id SharesToEncRequestID) String() string {
	return (uuid.UUID)(id).String()
}

type SharesToEncRequest struct {
	SessionID SessionID

	ReqID SharesToEncRequestID
	Query *SharesToEncQuery
}

type S2EConfig struct {
	SessionID SessionID
	CipherID  CipherID
}

func (cfg *S2EConfig) MarshalBinary() (data []byte, err error) {
	// Marshal SessionID
	sidData, err := cfg.SessionID.MarshalBinary()
	if err != nil {
		return
	}
	sidLen := len(sidData)

	// Marshal CipherID
	cidData, err := cfg.CipherID.MarshalBinary()
	if err != nil {
		return
	}
	cidLen := len(cidData)

	// Build data as [<sidLen>, <cidLen>, <SessionID>, <CipherID>]
	data = make([]byte, 8+8+sidLen+cidLen)
	ptr := 0 // Used to index data
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(sidLen))
	ptr += 8
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(cidLen))
	ptr += 8
	copy(data[ptr:ptr+sidLen], sidData)
	ptr += sidLen
	copy(data[ptr:ptr+cidLen], cidData)
	ptr += cidLen

	return
}
func (cfg *S2EConfig) UnmarshalBinary(data []byte) (err error) {
	ptr := 0 // Used to index data

	// Read lengths
	sidLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8
	cidLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8

	// Read fields
	if sidLen > 0 {
		err := cfg.SessionID.UnmarshalBinary(data[ptr : ptr+sidLen])
		ptr += sidLen
		if err != nil {
			return
		}
	}
	if cidLen > 0 {
		err := cfg.CipherID.UnmarshalBinary(data[ptr : ptr+cidLen])
		ptr += cidLen
		if err != nil {
			return
		}
	}

	return
}

/*
type SharesToEncBroadcast struct {
	SessionID SessionID

	ReqID SharesToEncRequestID
	// No params: it assumes it is already set. sigmaSmudging is extracted form params.Sigma in a static way.
	Params *S2EParameters
}
*/

type SharesToEncReply struct {
	SessionID SessionID

	ReqID SharesToEncRequestID
	// The CipherID will be the same
	Valid bool
}

type SharesToEncResponse struct {
	Valid bool
}
