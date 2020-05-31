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
	"sync"
)

// MsgTypes contains the different message types.
type MessageTypes struct {
	MsgCreateSessionQuery    network.MessageTypeID // Unused
	MsgCreateSessionResponse network.MessageTypeID // Unused

	MsgCloseSessionQuery    network.MessageTypeID // Unused
	MsgCloseSessionResponse network.MessageTypeID // Unused

	MsgGenPubKeyQuery    network.MessageTypeID // Unused
	MsgGenPubKeyResponse network.MessageTypeID // Unused

	MsgGenEvalKeyQuery    network.MessageTypeID // Unused
	MsgGenEvalKeyResponse network.MessageTypeID // Unused

	MsgGenRotKeyQuery    network.MessageTypeID // Unused
	MsgGenRotKeyResponse network.MessageTypeID // Unused

	MsgCreateCircuitQuery    network.MessageTypeID // Unused
	MsgCreateCircuitResponse network.MessageTypeID // Unused

	MsgGetPubKeyRequest network.MessageTypeID
	MsgGetPubKeyReply   network.MessageTypeID

	MsgGetEvalKeyRequest network.MessageTypeID
	MsgGetEvalKeyReply   network.MessageTypeID

	MsgGetRotKeyRequest network.MessageTypeID
	MsgGetRotKeyReply   network.MessageTypeID

	MsgStoreQuery    network.MessageTypeID // Unused
	MsgStoreResponse network.MessageTypeID // Unused

	MsgStoreAndNameQuery    network.MessageTypeID // Unused
	MsgStoreAndNameResponse network.MessageTypeID // Unused

	MsgNameQuery    network.MessageTypeID // Unused
	MsgNameResponse network.MessageTypeID // Unused

	MsgGetCipherRequest network.MessageTypeID
	MsgGetCipherReply   network.MessageTypeID

	MsgGetCipherIDRequest network.MessageTypeID
	MsgGetCipherIDReply   network.MessageTypeID

	MsgSwitchQuery    network.MessageTypeID // Unused
	MsgSwitchRequest  network.MessageTypeID
	MsgSwitchReply    network.MessageTypeID
	MsgSwitchResponse network.MessageTypeID // Unused

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

	MsgEvalCircuitQuery    network.MessageTypeID // Unused
	MsgEvalCircuitResponse network.MessageTypeID // Unused
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

	MsgTypes.MsgCreateCircuitQuery = network.RegisterMessage(&CreateCircuitQuery{})       // Unused
	MsgTypes.MsgCreateCircuitResponse = network.RegisterMessage(&CreateCircuitResponse{}) // Unused

	MsgTypes.MsgGetPubKeyRequest = network.RegisterMessage(&GetPubKeyRequest{})
	MsgTypes.MsgGetPubKeyReply = network.RegisterMessage(&GetPubKeyReply{})

	MsgTypes.MsgGetEvalKeyRequest = network.RegisterMessage(&GetEvalKeyRequest{})
	MsgTypes.MsgGetEvalKeyReply = network.RegisterMessage(&GetEvalKeyReply{})

	MsgTypes.MsgGetRotKeyRequest = network.RegisterMessage(&GetRotKeyRequest{})
	MsgTypes.MsgGetRotKeyReply = network.RegisterMessage(&GetRotKeyReply{})

	MsgTypes.MsgStoreQuery = network.RegisterMessage(&StoreQuery{})       // Unused
	MsgTypes.MsgStoreResponse = network.RegisterMessage(&StoreResponse{}) // Unused

	MsgTypes.MsgStoreAndNameQuery = network.RegisterMessage(&StoreAndNameQuery{})       // Unused
	MsgTypes.MsgStoreAndNameResponse = network.RegisterMessage(&StoreAndNameResponse{}) // Unused

	MsgTypes.MsgNameQuery = network.RegisterMessage(&NameQuery{})       // Unused
	MsgTypes.MsgNameResponse = network.RegisterMessage(&NameResponse{}) // Unused

	MsgTypes.MsgGetCipherRequest = network.RegisterMessage(&GetCipherRequest{})
	MsgTypes.MsgGetCipherReply = network.RegisterMessage(&GetCipherReply{})

	MsgTypes.MsgGetCipherIDRequest = network.RegisterMessage(&GetCipherIDRequest{})
	MsgTypes.MsgGetCipherIDReply = network.RegisterMessage(&GetCipherIDReply{})

	MsgTypes.MsgSwitchQuery = network.RegisterMessage(&SwitchQuery{}) // Unused
	MsgTypes.MsgSwitchRequest = network.RegisterMessage(&SwitchRequest{})
	MsgTypes.MsgSwitchReply = network.RegisterMessage(&SwitchReply{})
	MsgTypes.MsgSwitchResponse = network.RegisterMessage(&SwitchResponse{}) // Unused

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

	MsgTypes.MsgEvalCircuitQuery = network.RegisterMessage(&EvalCircuitQuery{})       // Unused
	MsgTypes.MsgEvalCircuitResponse = network.RegisterMessage(&EvalCircuitResponse{}) // Unused
}

/*********************** Message structs *********************/

// SessionID

type SessionID uuid.UUID

var NilSessionID = SessionID(uuid.Nil)

var sessIDLock sync.Mutex

func NewSessionID() SessionID {
	sessIDLock.Lock()
	defer sessIDLock.Unlock()
	return SessionID(uuid.NewV1())
}
func (id SessionID) String() string {
	return (uuid.UUID)(id).String()
}

// Circuit ID

type CircuitID uuid.UUID

var NilCircuitID = CircuitID(uuid.Nil)

var circIDLock sync.Mutex

func NewCircuitID() CircuitID {
	circIDLock.Lock()
	defer circIDLock.Unlock()
	return CircuitID(uuid.NewV1())
}
func (id CircuitID) String() string {
	return (uuid.UUID)(id).String()
}

// CipherID

type CipherID struct {
	Owner string
	ID    uuid.UUID
}

var NilCipherID = CipherID{"", uuid.Nil}

var cipIDLock sync.Mutex

func NewCipherID(owner *network.ServerIdentity) CipherID {
	cipIDLock.Lock()
	defer cipIDLock.Unlock()
	data, _ := protobuf.Encode(owner)
	return CipherID{string(data), uuid.NewV1()}
}
func (id CipherID) GetServerIdentityOwner() *network.ServerIdentity {
	owner := network.ServerIdentity{}
	_ = protobuf.Decode([]byte(id.Owner), &owner)
	return &owner
}
func (id CipherID) String() string {
	return "[Owner = " + id.GetServerIdentityOwner().String() + ", ID = " + id.ID.String() + "]"
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

type GenPubKeyConfig struct {
	SessionID SessionID
	Seed      []byte
}

type GenPubKeyResponse struct {
	MasterPublicKey *bfv.PublicKey
	Valid           bool
}

// Generate Evaluation Key

type GenEvalKeyQuery struct {
	SessionID SessionID
	Seed      []byte
}

type GenEvalKeyConfig struct {
	SessionID SessionID
	Seed      []byte
}

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

type GenRotKeyConfig struct {
	SessionID SessionID

	RotIdx int
	K      uint64
	Seed   []byte
}

type GenRotKeyResponse struct {
	Valid bool
}

// Get Public Key

type GetPubKeyRequestID uuid.UUID

var getPubKeyRIDLock sync.Mutex

func NewGetPubKeyRequestID() GetPubKeyRequestID {
	getPubKeyRIDLock.Lock()
	defer getPubKeyRIDLock.Unlock()
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

var getEvalKeyRIDLock sync.Mutex

func NewGetEvalKeyRequestID() GetEvalKeyRequestID {
	getEvalKeyRIDLock.Lock()
	defer getEvalKeyRIDLock.Unlock()
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

var getRotKeyRIDLock sync.Mutex

func NewGetRotKeyRequestID() GetRotKeyRequestID {
	getRotKeyRIDLock.Lock()
	defer getRotKeyRIDLock.Unlock()
	return GetRotKeyRequestID(uuid.NewV1())
}
func (id GetRotKeyRequestID) String() string {
	return (uuid.UUID)(id).String()
}

type GetRotKeyRequest struct {
	ReqID     GetRotKeyRequestID
	SessionID SessionID
	RotIdx    int
	K         uint64
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

// Store and name

// StoreAndNameQuery contains the data to store, and its variable name.
type StoreAndNameQuery struct {
	CircuitID CircuitID

	Name       string
	Ciphertext *bfv.Ciphertext
}

type StoreAndNameResponse struct {
	CipherID CipherID
	Valid    bool
}

// Name

// NameQuery contains the variable name.
type NameQuery struct {
	CircuitID CircuitID

	Name     string
	CipherID CipherID
}

type NameResponse struct {
	Valid bool
}

// Get Ciphertext

type GetCipherRequestID uuid.UUID

var getCipherRIDLock sync.Mutex

func NewGetCipherRequestID() GetCipherRequestID {
	getCipherRIDLock.Lock()
	defer getCipherRIDLock.Unlock()
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

// Get CipherID

type GetCipherIDRequestID uuid.UUID

var getCipherIDRIDLock sync.Mutex

func NewGetCipherIDRequestID() GetCipherIDRequestID {
	getCipherIDRIDLock.Lock()
	defer getCipherIDRIDLock.Unlock()
	return GetCipherIDRequestID(uuid.NewV1())
}
func (id GetCipherIDRequestID) String() string {
	return (uuid.UUID)(id).String()
}

type GetCipherIDRequest struct {
	ReqID     GetCipherIDRequestID
	CircuitID CircuitID
	Name      string
}

type GetCipherIDReply struct {
	ReqID GetCipherIDRequestID

	CipherID CipherID
	Valid    bool
}

// Switch

type SwitchQuery struct {
	SessionID SessionID

	CipherID  CipherID
	PublicKey *bfv.PublicKey
}

type SwitchRequestID uuid.UUID

var switchRIDLock sync.Mutex

func NewSwitchRequestID() SwitchRequestID {
	switchRIDLock.Lock()
	defer switchRIDLock.Unlock()
	return SwitchRequestID(uuid.NewV1())
}
func (id SwitchRequestID) String() string {
	return (uuid.UUID)(id).String()
}

type SwitchRequest struct {
	ReqID     SwitchRequestID
	SessionID SessionID

	CipherID  CipherID
	PublicKey *bfv.PublicKey
}

type SwitchConfig struct {
	SessionID  SessionID
	PublicKey  *bfv.PublicKey
	Ciphertext *bfv.Ciphertext
}

type SwitchReply struct {
	ReqID     SwitchRequestID
	SessionID SessionID

	Ciphertext *bfv.Ciphertext // Switched under the new public key
	Valid      bool
}

type SwitchResponse struct {
	Ciphertext *bfv.Ciphertext
	Valid      bool
}

// Sum

type SumQuery struct {
	SessionID SessionID

	CipherID1 CipherID
	CipherID2 CipherID
}

type SumRequestID uuid.UUID

var sumRIDLock sync.Mutex

func NewSumRequestID() SumRequestID {
	sumRIDLock.Lock()
	defer sumRIDLock.Unlock()
	return SumRequestID(uuid.NewV1())
}
func (id SumRequestID) String() string {
	return (uuid.UUID)(id).String()
}

type SumRequest struct {
	ReqID     SumRequestID
	SessionID SessionID

	CipherID1 CipherID
	CipherID2 CipherID
}

type SumReply struct {
	ReqID     SumRequestID
	SessionID SessionID

	NewCipherID CipherID
	Valid       bool
}

type SumResponse struct {
	NewCipherID CipherID
	Valid       bool
}

// Multiply

type MultiplyQuery struct {
	SessionID SessionID

	CipherID1 CipherID
	CipherID2 CipherID
}

type MultiplyRequestID uuid.UUID

var mulRIDLock sync.Mutex

func NewMultiplyRequestID() MultiplyRequestID {
	mulRIDLock.Lock()
	defer mulRIDLock.Unlock()
	return MultiplyRequestID(uuid.NewV1())
}
func (id MultiplyRequestID) String() string {
	return (uuid.UUID)(id).String()
}

type MultiplyRequest struct {
	ReqID     MultiplyRequestID
	SessionID SessionID

	CipherID1 CipherID
	CipherID2 CipherID
	WithRelin bool // Signals whether the called server should also relinearise
}

type MultiplyReply struct {
	ReqID     MultiplyRequestID
	SessionID SessionID

	NewCipherID CipherID
	Valid       bool
}

type MultiplyResponse struct {
	NewCipherID CipherID
	Valid       bool
}

// Relinearise

type RelinQuery struct {
	SessionID SessionID

	CipherID CipherID
}

type RelinRequestID uuid.UUID

var relinRIDLock sync.Mutex

func NewRelinRequestID() RelinRequestID {
	relinRIDLock.Lock()
	defer relinRIDLock.Unlock()
	return RelinRequestID(uuid.NewV1())
}
func (id RelinRequestID) String() string {
	return (uuid.UUID)(id).String()
}

type RelinRequest struct {
	ReqID     RelinRequestID
	SessionID SessionID

	CipherID CipherID
}

type RelinReply struct {
	ReqID     RelinRequestID
	SessionID SessionID

	NewCipherID CipherID
	Valid       bool
}

type RelinResponse struct {
	NewCipherID CipherID
	Valid       bool
}

// Refresh

type RefreshQuery struct {
	SessionID SessionID

	CipherID CipherID
	Seed     []byte
}

type RefreshRequestID uuid.UUID

var refreshRIDLock sync.Mutex

func NewRefreshRequestID() RefreshRequestID {
	refreshRIDLock.Lock()
	defer refreshRIDLock.Unlock()
	return RefreshRequestID(uuid.NewV1())
}
func (id RefreshRequestID) String() string {
	return (uuid.UUID)(id).String()
}

type RefreshRequest struct {
	ReqID     RefreshRequestID
	SessionID SessionID

	CipherID CipherID
	Seed     []byte
}

type RefreshConfig struct {
	SessionID  SessionID
	Ciphertext *bfv.Ciphertext
	Seed       []byte
}

type RefreshReply struct {
	ReqID     RefreshRequestID
	SessionID SessionID

	NewCipherID CipherID
	Valid       bool
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

var rotRIDLock sync.Mutex

func NewRotationRequestID() RotationRequestID {
	rotRIDLock.Lock()
	defer rotRIDLock.Unlock()
	return RotationRequestID(uuid.NewV1())
}
func (id RotationRequestID) String() string {
	return (uuid.UUID)(id).String()
}

type RotationRequest struct {
	ReqID     RotationRequestID
	SessionID SessionID

	CipherID CipherID
	K        uint64
	RotIdx   int
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

var e2sRIDLock sync.Mutex

func NewEncToSharesRequestID() EncToSharesRequestID {
	e2sRIDLock.Lock()
	defer e2sRIDLock.Unlock()
	return EncToSharesRequestID(uuid.NewV1())
}
func (id EncToSharesRequestID) String() string {
	return (uuid.UUID)(id).String()
}

type EncToSharesRequest struct {
	ReqID     EncToSharesRequestID
	SessionID SessionID

	CipherID CipherID
}

type E2SConfig struct {
	SessionID  SessionID
	SharesID   SharesID
	Ciphertext *bfv.Ciphertext
}

type EncToSharesReply struct {
	ReqID     EncToSharesRequestID
	SessionID SessionID

	SharesID SharesID
	Valid    bool
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

var s2eRIDLock sync.Mutex

func NewSharesToEncRequestID() SharesToEncRequestID {
	s2eRIDLock.Lock()
	defer s2eRIDLock.Unlock()
	return SharesToEncRequestID(uuid.NewV1())
}
func (id SharesToEncRequestID) String() string {
	return (uuid.UUID)(id).String()
}

type SharesToEncRequest struct {
	ReqID     SharesToEncRequestID
	SessionID SessionID

	SharesID SharesID
	Seed     []byte
}

type S2EConfig struct {
	SessionID SessionID
	SharesID  SharesID
	Seed      []byte
}

type SharesToEncReply struct {
	ReqID     SharesToEncRequestID
	SessionID SessionID

	NewCipherID CipherID
	Valid       bool
}

type SharesToEncResponse struct {
	NewCipherID CipherID
	Valid       bool
}

// Create circuit

type CreateCircuitQuery struct {
	SessionID SessionID

	Desc string // RPN description of the circuit
}

type CreateCircuitConfig struct {
	SessionID   SessionID
	CircuitID   CircuitID
	Description string
}

type CreateCircuitResponse struct {
	CircuitID CircuitID
	Valid     bool
}

// Evaluate circuit

type EvalCircuitQuery struct {
	CircuitID CircuitID
}

type CloseCircuitConfig struct {
	CircuitID CircuitID
}

type EvalCircuitResponse struct {
	Result CipherID
	Valid  bool
}
