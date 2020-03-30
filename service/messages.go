// This file defines the data structure for every message exchanged "directly" (i.e. except those exchanged,
// for example, by the protocols) by the service, both for client-server and server-root interaction.
// It also defines a data structure containing the MessageTypeID of all those messages.
// It also registers those message types to the underlying onet library, with the init method.

package service

import (
	"github.com/ldsec/lattigo/bfv"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
	uuid "gopkg.in/satori/go.uuid.v1"
	"lattigo-smc/protocols"
)

// MsgTypes contains the different message types.
type MsgTypes struct {
	msgSetupQuery     network.MessageTypeID // Unused
	msgSetupRequest   network.MessageTypeID
	msgSetupBroadcast network.MessageTypeID
	msgSetupReply     network.MessageTypeID
	msgSetupResponse  network.MessageTypeID // Unused

	msgKeyQuery    network.MessageTypeID // Unused
	msgKeyRequest  network.MessageTypeID
	msgKeyReply    network.MessageTypeID
	msgKeyResponse network.MessageTypeID // Unused

	msgStoreQuery    network.MessageTypeID // Unused
	msgStoreRequest  network.MessageTypeID
	msgStoreReply    network.MessageTypeID
	msgStoreResponse network.MessageTypeID // Unused

	msgRetrieveQuery     network.MessageTypeID // Unused
	msgRetrieveRequest   network.MessageTypeID
	msgRetrieveBroadcast network.MessageTypeID
	msgRetrieveReply     network.MessageTypeID
	msgRetrieveResponse  network.MessageTypeID // Unused

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

	msgRefreshQuery     network.MessageTypeID // Unused
	msgRefreshRequest   network.MessageTypeID
	msgRefreshBroadcast network.MessageTypeID
	msgRefreshReply     network.MessageTypeID
	msgRefreshResponse  network.MessageTypeID // Unused

	msgRotationQuery    network.MessageTypeID // Unused
	msgRotationRequest  network.MessageTypeID
	msgRotationReply    network.MessageTypeID
	msgRotationResponse network.MessageTypeID // Unused
}

var msgTypes = MsgTypes{}

// Registers all the message types to the onet library
func init() {
	log.Lvl1("Registering messages")

	msgTypes.msgSetupQuery = network.RegisterMessage(&SetupQuery{}) // Unused
	msgTypes.msgSetupRequest = network.RegisterMessage(&SetupRequest{})
	msgTypes.msgSetupBroadcast = network.RegisterMessage(&SetupBroadcast{})
	msgTypes.msgSetupReply = network.RegisterMessage(&SetupReply{})
	msgTypes.msgSetupResponse = network.RegisterMessage(&SetupResponse{}) // Unused

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
	msgTypes.msgRetrieveBroadcast = network.RegisterMessage(&RetrieveBroadcast{})
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
	msgTypes.msgRefreshBroadcast = network.RegisterMessage(&RefreshBroadcast{})
	msgTypes.msgRefreshReply = network.RegisterMessage(&RefreshReply{})
	msgTypes.msgRefreshResponse = network.RegisterMessage(&RefreshResponse{}) // Unused

	msgTypes.msgRotationQuery = network.RegisterMessage(&RotationQuery{}) // Unused
	msgTypes.msgRotationRequest = network.RegisterMessage(&RotationRequest{})
	msgTypes.msgRotationReply = network.RegisterMessage(&RotationReply{})
	msgTypes.msgRotationResponse = network.RegisterMessage(&RotationResponse{}) // Unused

	_ = network.RegisterMessage(&protocols.Start{}) // TODO: necessary?
}

/*********************** Message structs *********************/

type CipherID uuid.UUID

var nilCipherID = CipherID(uuid.Nil)

func newCipherID() CipherID {
	return CipherID(uuid.NewV1())
}

// TODO: why a query? Why not load from cfg file?
type SetupQuery struct {
	Roster onet.Roster

	ParamsIdx             uint64
	Seed                  []byte
	GeneratePublicKey     bool
	GenerateEvaluationKey bool
	GenerateRotationKey   bool
	K                     uint64
	RotIdx                int
}

type SetupRequestID uuid.UUID

func newSetupRequestID() SetupRequestID {
	return SetupRequestID(uuid.NewV1())
}

type SetupRequest struct {
	SetupRequestID
	*SetupQuery
}

type SetupBroadcast SetupRequest

type SetupReply struct {
	SetupRequestID

	pubKeyGenerated  bool
	evalKeyGenerated bool
	rotKeyGenerated  bool
}

type SetupResponse struct {
	PubKeyGenerated  bool
	EvalKeyGenerated bool
	RotKeyGenerated  bool
}

type KeyQuery struct {
	PublicKey     bool
	EvaluationKey bool
	RotationKey   bool
	RotIdx        int
}

type KeyRequestID uuid.UUID

func newKeyRequestID() KeyRequestID {
	return KeyRequestID(uuid.NewV1())
}

type KeyRequest struct {
	KeyRequestID
	*KeyQuery
}

// KeyReply is sent by root to server, in response to KeyQuery.
// Contains the requested keys, if they exist.
type KeyReply struct {
	KeyRequestID

	pk     *bfv.PublicKey
	evk    *bfv.EvaluationKey
	rtk    *bfv.RotationKeys
	RotIdx int
}

type KeyResponse struct {
	PubKeyObtained  bool
	EvalKeyObtained bool
	RotKeyObtained  bool
}

// StoreQuery contains the data to store.
type StoreQuery struct {
	Ciphertext *bfv.Ciphertext
}

type StoreRequestID uuid.UUID

func newStoreRequestID() StoreRequestID {
	return StoreRequestID(uuid.NewV1())
}

// StoreRequest is sent by server to root.
// Contains new ciphertext to store.
type StoreRequest struct {
	StoreRequestID
	*StoreQuery
}

type StoreReply struct {
	StoreRequestID

	cipherID CipherID
}

type StoreResponse struct {
	CipherID CipherID
}

//RetrieveQuery query for a ciphertext represented by ID to be switched under PublicKey
type RetrieveQuery struct {
	PublicKey *bfv.PublicKey
	CipherID  CipherID
}

type RetrieveRequestID uuid.UUID

func newRetrieveRequestID() RetrieveRequestID {
	return RetrieveRequestID(uuid.NewV1())
}

type RetrieveRequest struct {
	RetrieveRequestID
	*RetrieveQuery
}

type RetrieveBroadcast struct {
	RetrieveRequestID
	params *SwitchingParameters
}

//RetrieveReply contains the ciphertext switched under the key requested.
type RetrieveReply struct {
	RetrieveRequestID

	ciphertext *bfv.Ciphertext
	valid      bool
}

type RetrieveResponse struct {
	Ciphertext *bfv.Ciphertext
	Valid      bool
}

// Client asks to sum ciphertexts ID1 and ID2.
type SumQuery struct {
	CipherID1 CipherID
	CipherID2 CipherID
}

// Server further assigns an ID to the query
type SumRequestID uuid.UUID

func newSumRequestID() SumRequestID {
	return SumRequestID(uuid.NewV1())
}

// Message sent by server to root.
type SumRequest struct {
	SumRequestID
	*SumQuery
}

// Root answers with the same SumRequestID, the CipherID of the new ciphertext,
// and a flag indicating whether the operation succeeded.
type SumReply struct {
	SumRequestID

	newCipherID CipherID
	valid       bool
}

type SumResponse struct {
	NewCipherID CipherID
	Valid       bool
}

// Client asks to multiply ID1 and ID2
type MultiplyQuery struct {
	CipherID1 CipherID
	CipherID2 CipherID
}

type MultiplyRequestID uuid.UUID

func newMultiplyRequestID() MultiplyRequestID {
	return MultiplyRequestID(uuid.NewV1())
}

// Message sent by server to root.
type MultiplyRequest struct {
	MultiplyRequestID
	*MultiplyQuery
}

// Root answers with the same SumRequestID, the CipherID of the new ciphertext,
// and a flag indicating whether the operation succeeded.
type MultiplyReply struct {
	MultiplyRequestID
	newCipherID CipherID
	valid       bool
}

type MultiplyResponse struct {
	NewCipherID CipherID
	Valid       bool
}

// Client asks to relinearise the given CipherID
type RelinQuery struct {
	CipherID CipherID
}

type RelinRequestID uuid.UUID

func newRelinRequestID() RelinRequestID {
	return RelinRequestID(uuid.NewV1())
}

type RelinRequest struct {
	RelinRequestID
	*RelinQuery
}

type RelinReply struct {
	RelinRequestID
	valid bool
}

type RelinResponse struct {
	Valid bool
}

//RefreshQuery query for ID1 to be refreshed.
type RefreshQuery struct {
	CipherID CipherID
}

type RefreshRequestID uuid.UUID

func newRefreshRequestID() RefreshRequestID {
	return RefreshRequestID(uuid.NewV1())
}

type RefreshRequest struct {
	RefreshRequestID
	*RefreshQuery
}

type RefreshBroadcast struct {
	RefreshRequestID
	ct *bfv.Ciphertext
}

type RefreshReply struct {
	RefreshRequestID

	valid bool
}

type RefreshResponse struct {
	Valid bool
}

type RotationQuery struct {
	CipherID CipherID
	K        uint64
	RotIdx   int
}

type RotationRequestID uuid.UUID

func newRotationRequestID() RotationRequestID {
	return RotationRequestID(uuid.NewV1())
}

type RotationRequest struct {
	RotationRequestID
	*RotationQuery
}

type RotationReply struct {
	RotationRequestID

	Old   CipherID
	New   CipherID
	valid bool
}

type RotationResponse struct {
	Old   CipherID
	New   CipherID
	Valid bool
}
