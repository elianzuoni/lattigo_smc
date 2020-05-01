// This file defines the data structure for every message exchanged "directly" (i.e. except those exchanged,
// for example, by the protocols) by the service, both for client-server and server-root interaction.
// It also defines a data structure containing the MessageTypeID of all those messages.
// It also registers those message types to the underlying onet library, with the init method.

package messages

import (
	"github.com/ldsec/lattigo/bfv"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
	"go.dedis.ch/protobuf"
	uuid "gopkg.in/satori/go.uuid.v1"
)

// MsgTypes contains the different message types.
type MessageTypes struct {
	MsgCreateSessionQuery    network.MessageTypeID // Unused
	MsgCreateSessionResponse network.MessageTypeID // Unused

	MsgCloseSessionQuery    network.MessageTypeID // Unused
	MsgCloseSessionResponse network.MessageTypeID // Unused

	MsgGenPubKeyQuery network.MessageTypeID // Unused
	/*
		MsgGenPubKeyRequest  network.MessageTypeID
		MsgGenPubKeyReply    network.MessageTypeID

	*/
	MsgGenPubKeyResponse network.MessageTypeID // Unused

	MsgGenEvalKeyQuery network.MessageTypeID // Unused
	/*
		MsgGenEvalKeyRequest  network.MessageTypeID
		MsgGenEvalKeyReply    network.MessageTypeID

	*/
	MsgGenEvalKeyResponse network.MessageTypeID // Unused

	MsgGenRotKeyQuery network.MessageTypeID // Unused
	/*
		MsgGenRotKeyRequest  network.MessageTypeID
		MsgGenRotKeyReply    network.MessageTypeID

	*/
	MsgGenRotKeyResponse network.MessageTypeID // Unused

	MsgGetPubKeyRequest network.MessageTypeID
	MsgGetPubKeyReply   network.MessageTypeID

	MsgGetEvalKeyRequest network.MessageTypeID
	MsgGetEvalKeyReply   network.MessageTypeID

	MsgGetRotKeyRequest network.MessageTypeID
	MsgGetRotKeyReply   network.MessageTypeID

	MsgStoreQuery    network.MessageTypeID // Unused
	MsgStoreResponse network.MessageTypeID // Unused

	MsgGetCipherRequest network.MessageTypeID
	MsgGetCipherReply   network.MessageTypeID

	MsgRetrieveQuery    network.MessageTypeID // Unused
	MsgRetrieveRequest  network.MessageTypeID
	MsgRetrieveReply    network.MessageTypeID
	MsgRetrieveResponse network.MessageTypeID // Unused

	MsgSumQuery    network.MessageTypeID // Unused
	MsgSumRequest  network.MessageTypeID
	MsgSumReply    network.MessageTypeID
	MsgSumResponse network.MessageTypeID // Unused

	MsgMultiplyQuery    network.MessageTypeID // Unused
	MsgMultiplyRequest  network.MessageTypeID
	MsgMultiplyReply    network.MessageTypeID
	MsgMultiplyResponse network.MessageTypeID // Unused

	MsgRelinQuery    network.MessageTypeID // Unused
	MsgRelinRequest  network.MessageTypeID
	MsgRelinReply    network.MessageTypeID
	MsgRelinResponse network.MessageTypeID // Unused

	MsgRefreshQuery    network.MessageTypeID // Unused
	MsgRefreshRequest  network.MessageTypeID
	MsgRefreshReply    network.MessageTypeID
	MsgRefreshResponse network.MessageTypeID // Unused

	MsgRotationQuery    network.MessageTypeID // Unused
	MsgRotationRequest  network.MessageTypeID
	MsgRotationReply    network.MessageTypeID
	MsgRotationResponse network.MessageTypeID // Unused

	MsgEncToSharesQuery    network.MessageTypeID // Unused
	MsgEncToSharesRequest  network.MessageTypeID
	MsgEncToSharesReply    network.MessageTypeID
	MsgEncToSharesResponse network.MessageTypeID // Unused

	MsgSharesToEncQuery    network.MessageTypeID // Unused
	MsgSharesToEncRequest  network.MessageTypeID
	MsgSharesToEncReply    network.MessageTypeID
	MsgSharesToEncResponse network.MessageTypeID // Unused
}

var MsgTypes = MessageTypes{}

// Registers all the message types to the onet library
func init() {
	log.Lvl1("Registering messages")

	MsgTypes.MsgCreateSessionQuery = network.RegisterMessage(&CreateSessionQuery{})       // Unused
	MsgTypes.MsgCreateSessionResponse = network.RegisterMessage(&CreateSessionResponse{}) // Unused

	MsgTypes.MsgCloseSessionQuery = network.RegisterMessage(&CloseSessionQuery{})       // Unused
	MsgTypes.MsgCloseSessionResponse = network.RegisterMessage(&CloseSessionResponse{}) // Unused

	MsgTypes.MsgGenPubKeyQuery = network.RegisterMessage(&GenPubKeyQuery{})       // Unused
	MsgTypes.MsgGenPubKeyResponse = network.RegisterMessage(&GenPubKeyResponse{}) // Unused

	MsgTypes.MsgGenEvalKeyQuery = network.RegisterMessage(&GenEvalKeyQuery{})       // Unused
	MsgTypes.MsgGenEvalKeyResponse = network.RegisterMessage(&GenEvalKeyResponse{}) // Unused

	MsgTypes.MsgGenRotKeyQuery = network.RegisterMessage(&GenRotKeyQuery{})       // Unused
	MsgTypes.MsgGenRotKeyResponse = network.RegisterMessage(&GenRotKeyResponse{}) // Unused

	MsgTypes.MsgGetPubKeyRequest = network.RegisterMessage(&GetPubKeyRequest{})
	MsgTypes.MsgGetPubKeyReply = network.RegisterMessage(&GetPubKeyReply{})

	MsgTypes.MsgGetEvalKeyRequest = network.RegisterMessage(&GetEvalKeyRequest{})
	MsgTypes.MsgGetEvalKeyReply = network.RegisterMessage(&GetEvalKeyReply{})

	MsgTypes.MsgGetRotKeyRequest = network.RegisterMessage(&GetRotKeyRequest{})
	MsgTypes.MsgGetRotKeyReply = network.RegisterMessage(&GetRotKeyReply{})

	MsgTypes.MsgStoreQuery = network.RegisterMessage(&StoreQuery{})       // Unused
	MsgTypes.MsgStoreResponse = network.RegisterMessage(&StoreResponse{}) // Unused

	MsgTypes.MsgGetCipherRequest = network.RegisterMessage(&GetCipherRequest{})
	MsgTypes.MsgGetCipherReply = network.RegisterMessage(&GetCipherReply{})

	MsgTypes.MsgRetrieveQuery = network.RegisterMessage(&RetrieveQuery{}) // Unused
	MsgTypes.MsgRetrieveRequest = network.RegisterMessage(&RetrieveRequest{})
	MsgTypes.MsgRetrieveReply = network.RegisterMessage(&RetrieveReply{})
	MsgTypes.MsgRetrieveResponse = network.RegisterMessage(&RetrieveResponse{}) // Unused

	MsgTypes.MsgSumQuery = network.RegisterMessage(&SumQuery{}) // Unused
	MsgTypes.MsgSumRequest = network.RegisterMessage(&SumRequest{})
	MsgTypes.MsgSumReply = network.RegisterMessage(&SumReply{})
	MsgTypes.MsgSumResponse = network.RegisterMessage(&SumResponse{}) // Unused

	MsgTypes.MsgMultiplyQuery = network.RegisterMessage(&MultiplyQuery{}) // Unused
	MsgTypes.MsgMultiplyRequest = network.RegisterMessage(&MultiplyRequest{})
	MsgTypes.MsgMultiplyReply = network.RegisterMessage(&MultiplyReply{})
	MsgTypes.MsgMultiplyResponse = network.RegisterMessage(&MultiplyResponse{}) // Unused

	MsgTypes.MsgRelinQuery = network.RegisterMessage(&RelinQuery{}) // Unused
	MsgTypes.MsgRelinRequest = network.RegisterMessage(&RelinRequest{})
	MsgTypes.MsgRelinReply = network.RegisterMessage(&RelinReply{})
	MsgTypes.MsgRelinResponse = network.RegisterMessage(&RelinResponse{}) // Unused

	MsgTypes.MsgRefreshQuery = network.RegisterMessage(&RefreshQuery{}) // Unused
	MsgTypes.MsgRefreshRequest = network.RegisterMessage(&RefreshRequest{})
	MsgTypes.MsgRefreshReply = network.RegisterMessage(&RefreshReply{})
	MsgTypes.MsgRefreshResponse = network.RegisterMessage(&RefreshResponse{}) // Unused

	MsgTypes.MsgRotationQuery = network.RegisterMessage(&RotationQuery{}) // Unused
	MsgTypes.MsgRotationRequest = network.RegisterMessage(&RotationRequest{})
	MsgTypes.MsgRotationReply = network.RegisterMessage(&RotationReply{})
	MsgTypes.MsgRotationResponse = network.RegisterMessage(&RotationResponse{}) // Unused

	MsgTypes.MsgEncToSharesQuery = network.RegisterMessage(&EncToSharesQuery{}) // Unused
	MsgTypes.MsgEncToSharesRequest = network.RegisterMessage(&EncToSharesRequest{})
	MsgTypes.MsgEncToSharesReply = network.RegisterMessage(&EncToSharesReply{})
	MsgTypes.MsgEncToSharesResponse = network.RegisterMessage(&EncToSharesResponse{}) // Unused

	MsgTypes.MsgSharesToEncQuery = network.RegisterMessage(&SharesToEncQuery{}) // Unused
	MsgTypes.MsgSharesToEncRequest = network.RegisterMessage(&SharesToEncRequest{})
	MsgTypes.MsgSharesToEncReply = network.RegisterMessage(&SharesToEncReply{})
	MsgTypes.MsgSharesToEncResponse = network.RegisterMessage(&SharesToEncResponse{}) // Unused
}

/*********************** Message structs *********************/

// SessionID

type SessionID uuid.UUID

var NilSessionID = SessionID(uuid.Nil)

func NewSessionID() SessionID {
	return SessionID(uuid.NewV1())
}
func (id SessionID) String() string {
	return (uuid.UUID)(id).String()
}

// CipherID

type CipherID struct {
	Owner string // TODO: this is an ugly workaround
	ID    uuid.UUID
}

var NilCipherID = CipherID{"", uuid.Nil}

func NewCipherID(owner *network.ServerIdentity) CipherID {
	data, _ := protobuf.Encode(owner)
	return CipherID{string(data), uuid.NewV1()}
}
func (id CipherID) GetServerIdentityOwner() *network.ServerIdentity {
	owner := network.ServerIdentity{}
	_ = protobuf.Decode([]byte(id.Owner), &owner)
	return &owner
}
func (id CipherID) String() string {
	return id.GetServerIdentityOwner().String() + ":" + id.ID.String()
}

// SharesID

type SharesID uuid.UUID

var NilSharesID = SharesID(uuid.Nil)

func NewSharesID() SharesID {
	return SharesID(uuid.NewV1())
}
func (id SharesID) String() string {
	return (uuid.UUID)(id).String()
}

// Create Session

type CreateSessionQuery struct {
	Roster *onet.Roster
	Params *bfv.Parameters
}

type CreateSessionConfig struct {
	SessionID SessionID
	Roster    *onet.Roster
	Params    *bfv.Parameters
}

type CreateSessionResponse struct {
	SessionID SessionID
	Valid     bool
}

// Close Session

type CloseSessionQuery struct {
	SessionID SessionID
}

type CloseSessionConfig struct {
	SessionID SessionID
}

type CloseSessionResponse struct {
	Valid bool
}

// Generate Public Key

type GenPubKeyQuery struct {
	SessionID SessionID
	Seed      []byte
}

/*
type GenPubKeyRequestID uuid.UUID

func NewGenPubKeyRequestID() GenPubKeyRequestID {
	return GenPubKeyRequestID(uuid.NewV1())
}
func (id GenPubKeyRequestID) String() string {
	return (uuid.UUID)(id).String()
}

type GenPubKeyRequest struct {
	SessionID SessionID
	ReqID     GenPubKeyRequestID
	Query     *GenPubKeyQuery
}

*/

type GenPubKeyConfig struct {
	SessionID SessionID
	Seed      []byte
}

/*
type GenPubKeyReply struct {
	SessionID SessionID
	ReqID     GenPubKeyRequestID

	MasterPublicKey *bfv.PublicKey
	Valid           bool
}

*/

type GenPubKeyResponse struct {
	MasterPublicKey *bfv.PublicKey
	Valid           bool
}

// Generate Evaluation Key

type GenEvalKeyQuery struct {
	SessionID SessionID
	Seed      []byte
}

/*
type GenEvalKeyRequestID uuid.UUID

func NewGenEvalKeyRequestID() GenEvalKeyRequestID {
	return GenEvalKeyRequestID(uuid.NewV1())
}
func (id GenEvalKeyRequestID) String() string {
	return (uuid.UUID)(id).String()
}

type GenEvalKeyRequest struct {
	SessionID SessionID
	ReqID     GenEvalKeyRequestID
	Query     *GenEvalKeyQuery
}

*/

type GenEvalKeyConfig struct {
	SessionID SessionID
	Seed      []byte
}

/*
type GenEvalKeyReply struct {
	SessionID SessionID
	ReqID     GenEvalKeyRequestID

	Valid bool
}

*/

type GenEvalKeyResponse struct {
	Valid bool
}

// Generate Rotation Key

type GenRotKeyQuery struct {
	SessionID SessionID
	RotIdx    int
	K         uint64
	Seed      []byte
}

/*
type GenRotKeyRequestID uuid.UUID

func NewGenRotKeyRequestID() GenRotKeyRequestID {
	return GenRotKeyRequestID(uuid.NewV1())
}
func (id GenRotKeyRequestID) String() string {
	return (uuid.UUID)(id).String()
}


type GenRotKeyRequest struct {
	SessionID SessionID
	ReqID     GenRotKeyRequestID
	Query     *GenRotKeyQuery
}

*/

type GenRotKeyConfig struct {
	SessionID SessionID

	RotIdx int
	K      uint64
	Seed   []byte
}

/*
type GenRotKeyReply struct {
	SessionID SessionID
	ReqID     GenRotKeyRequestID

	Valid bool
}

*/

type GenRotKeyResponse struct {
	Valid bool
}

// Get Public Key

type GetPubKeyRequestID uuid.UUID

func NewGetPubKeyRequestID() GetPubKeyRequestID {
	return GetPubKeyRequestID(uuid.NewV1())
}
func (id GetPubKeyRequestID) String() string {
	return (uuid.UUID)(id).String()
}

type GetPubKeyRequest struct {
	ReqID GetPubKeyRequestID

	SessionID SessionID
}

type GetPubKeyReply struct {
	ReqID GetPubKeyRequestID

	PublicKey *bfv.PublicKey
	Valid     bool
}

// Get Evaluation Key

type GetEvalKeyRequestID uuid.UUID

func NewGetEvalKeyRequestID() GetEvalKeyRequestID {
	return GetEvalKeyRequestID(uuid.NewV1())
}
func (id GetEvalKeyRequestID) String() string {
	return (uuid.UUID)(id).String()
}

type GetEvalKeyRequest struct {
	ReqID     GetEvalKeyRequestID
	SessionID SessionID
}

type GetEvalKeyReply struct {
	ReqID GetEvalKeyRequestID

	EvaluationKey *bfv.EvaluationKey
	Valid         bool
}

// Get Rotation Key

type GetRotKeyRequestID uuid.UUID

func NewGetRotKeyRequestID() GetRotKeyRequestID {
	return GetRotKeyRequestID(uuid.NewV1())
}
func (id GetRotKeyRequestID) String() string {
	return (uuid.UUID)(id).String()
}

type GetRotKeyRequest struct {
	ReqID     GetRotKeyRequestID
	SessionID SessionID
}

type GetRotKeyReply struct {
	ReqID GetRotKeyRequestID

	RotationKey *bfv.RotationKeys
	Valid       bool
}

// Store

// StoreQuery contains the data to store.
type StoreQuery struct {
	SessionID SessionID

	Ciphertext *bfv.Ciphertext
}

type StoreResponse struct {
	CipherID CipherID
	Valid    bool
}

// Get Ciphertext

type GetCipherRequestID uuid.UUID

func NewGetCipherRequestID() GetCipherRequestID {
	return GetCipherRequestID(uuid.NewV1())
}
func (id GetCipherRequestID) String() string {
	return (uuid.UUID)(id).String()
}

type GetCipherRequest struct {
	ReqID     GetCipherRequestID
	SessionID SessionID
	CipherID  CipherID
}

type GetCipherReply struct {
	ReqID GetCipherRequestID

	Ciphertext *bfv.Ciphertext
	Valid      bool
}

// Retrieve

//RetrieveQuery query for a ciphertext represented by ID to be switched under PublicKey
type RetrieveQuery struct {
	SessionID SessionID

	PublicKey *bfv.PublicKey
	CipherID  CipherID
}

type RetrieveRequestID uuid.UUID

func NewRetrieveRequestID() RetrieveRequestID {
	return RetrieveRequestID(uuid.NewV1())
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

func NewSumRequestID() SumRequestID {
	return SumRequestID(uuid.NewV1())
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

// Root answers with the same SumRequestID, the CipherID of the New ciphertext,
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

func NewMultiplyRequestID() MultiplyRequestID {
	return MultiplyRequestID(uuid.NewV1())
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

// Root answers with the same SumRequestID, the CipherID of the New ciphertext,
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

func NewRelinRequestID() RelinRequestID {
	return RelinRequestID(uuid.NewV1())
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

	ReqID       RelinRequestID
	NewCipherID CipherID

	Valid bool
}

type RelinResponse struct {
	NewCipherID CipherID
	Valid       bool
}

// Refresh

//RefreshQuery query for ID1 to be refreshed.
type RefreshQuery struct {
	SessionID SessionID

	CipherID CipherID
	Seed     []byte
}

type RefreshRequestID uuid.UUID

func NewRefreshRequestID() RefreshRequestID {
	return RefreshRequestID(uuid.NewV1())
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
	Seed       []byte
}

type RefreshReply struct {
	SessionID SessionID

	ReqID       RefreshRequestID
	NewCipherID CipherID

	Valid bool
}

type RefreshResponse struct {
	NewCipherID CipherID
	Valid       bool
}

// Rotation

type RotationQuery struct {
	SessionID SessionID

	CipherID CipherID
	K        uint64
	RotIdx   int
}

type RotationRequestID uuid.UUID

func NewRotationRequestID() RotationRequestID {
	return RotationRequestID(uuid.NewV1())
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

func NewEncToSharesRequestID() EncToSharesRequestID {
	return EncToSharesRequestID(uuid.NewV1())
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
	SharesID   SharesID
	Ciphertext *bfv.Ciphertext
}

type EncToSharesReply struct {
	SessionID SessionID

	ReqID    EncToSharesRequestID
	SharesID SharesID

	Valid bool
}

type EncToSharesResponse struct {
	SharesID SharesID
	Valid    bool
}

// Shares to encryption

type SharesToEncQuery struct {
	SessionID SessionID

	SharesID SharesID
	Seed     []byte
}

type SharesToEncRequestID uuid.UUID

func NewSharesToEncRequestID() SharesToEncRequestID {
	return SharesToEncRequestID(uuid.NewV1())
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
	SharesID  SharesID
	Seed      []byte
}

type SharesToEncReply struct {
	SessionID SessionID

	ReqID       SharesToEncRequestID
	NewCipherID CipherID

	Valid bool
}

type SharesToEncResponse struct {
	NewCipherID CipherID
	Valid       bool
}
