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

// MsgTypes contains the different message types that can be received.
type MsgTypes struct {
	msgSetupQuery     network.MessageTypeID // Unused
	msgSetupRequest   network.MessageTypeID
	msgSetupBroadcast network.MessageTypeID

	msgKeyQuery   network.MessageTypeID // Unused
	msgKeyRequest network.MessageTypeID
	msgKeyReply   network.MessageTypeID

	msgStoreQuery   network.MessageTypeID // Unused
	msgStoreRequest network.MessageTypeID

	msgRetrieveQuery     network.MessageTypeID
	msgRetrieveRequest   network.MessageTypeID
	msgRetrieveBroadcast network.MessageTypeID
	msgRetrieveReply     network.MessageTypeID

	msgSumQuery   network.MessageTypeID // Unused
	msgSumRequest network.MessageTypeID
	msgSumReply   network.MessageTypeID

	msgMultiplyQuery   network.MessageTypeID // Unused
	msgMultiplyRequest network.MessageTypeID
	msgMultiplyReply   network.MessageTypeID

	msgRelinQuery   network.MessageTypeID
	msgRelinRequest network.MessageTypeID

	msgRefreshQuery     network.MessageTypeID
	msgRefreshRequest   network.MessageTypeID
	msgRefreshBroadcast network.MessageTypeID
	msgRefreshReply     network.MessageTypeID

	msgRotationQuery   network.MessageTypeID
	msgRotationRequest network.MessageTypeID
	msgRotationReply   network.MessageTypeID
}

var msgTypes = MsgTypes{}

// Registers all the message types to the onet library
func init() { // TODO: complete
	log.Lvl1("Registering messages")

	msgTypes.msgSetupQuery = network.RegisterMessage(&SetupQuery{}) // Unused
	msgTypes.msgSetupRequest = network.RegisterMessage(&SetupRequest{})
	msgTypes.msgSetupBroadcast = network.RegisterMessage(&SetupBroadcast{})

	msgTypes.msgKeyQuery = network.RegisterMessage(&KeyQuery{}) // Unused
	msgTypes.msgKeyRequest = network.RegisterMessage(&KeyRequest{})
	msgTypes.msgKeyReply = network.RegisterMessage(&KeyReply{})

	msgTypes.msgStoreQuery = network.RegisterMessage(&StoreQuery{}) // Unused
	msgTypes.msgStoreRequest = network.RegisterMessage(&StoreRequest{})

	msgTypes.msgRetrieveQuery = network.RegisterMessage(&RetrieveQuery{}) // Unused
	msgTypes.msgRetrieveRequest = network.RegisterMessage(&RetrieveRequest{})
	msgTypes.msgRetrieveBroadcast = network.RegisterMessage(&RetrieveBroadcast{})
	msgTypes.msgRetrieveReply = network.RegisterMessage(&RetrieveReply{})

	msgTypes.msgSumQuery = network.RegisterMessage(&SumQuery{}) // Unused
	msgTypes.msgSumRequest = network.RegisterMessage(&SumRequest{})
	msgTypes.msgSumReply = network.RegisterMessage(&SumReply{})

	msgTypes.msgMultiplyQuery = network.RegisterMessage(&MultiplyQuery{}) // Unused
	msgTypes.msgMultiplyRequest = network.RegisterMessage(&MultiplyRequest{})
	msgTypes.msgMultiplyReply = network.RegisterMessage(&MultiplyReply{})

	msgTypes.msgRelinQuery = network.RegisterMessage(&RelinQuery{}) // Unused
	msgTypes.msgRelinRequest = network.RegisterMessage(&RelinRequest{})

	msgTypes.msgRefreshQuery = network.RegisterMessage(&RefreshQuery{}) // Unused
	msgTypes.msgRefreshRequest = network.RegisterMessage(&RefreshRequest{})
	msgTypes.msgRefreshBroadcast = network.RegisterMessage(&RefreshBroadcast{})
	msgTypes.msgRefreshReply = network.RegisterMessage(&RefreshReply{})

	msgTypes.msgRotationQuery = network.RegisterMessage(&RotationQuery{}) // Unused
	msgTypes.msgRotationRequest = network.RegisterMessage(&RotationRequest{})
	msgTypes.msgRotationReply = network.RegisterMessage(&RotationReply{})

	_ = network.RegisterMessage(&protocols.Start{}) // TODO: necessary?
}

/*********************** Message structs *********************/

type CipherID uuid.UUID

var nilCipherID = CipherID(uuid.Nil)

// TODO: remove
type ServiceState struct {
	Id      CipherID
	Pending bool
}

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

type SetupRequest SetupQuery

type SetupBroadcast SetupQuery

// KeyQuery is sent by client to server, and forwarded by server to root.
// Contains flag signalling which keys to retrieve.
type KeyQuery struct {
	PublicKey     bool
	EvaluationKey bool
	RotationKey   bool
	RotIdx        int
}

// KeyRequest is sent by the server to the root.
type KeyRequest KeyQuery

// KeyReply is sent by root to server, in response to KeyQuery.
// Contains the requested keys, if they exist.
type KeyReply struct {
	*bfv.PublicKey
	*bfv.EvaluationKey
	*bfv.RotationKeys
	RotIdx int
}

// StoreQuery contains the data to encrypt and store.
type StoreQuery struct {
	Roster onet.Roster // TODO: why?
	Data   []byte
}

// StoreRequest is sent by server to root.
// Contains new ciphertext to store, and a CipherID (generated by the server)
type StoreRequest struct {
	Ciphertext *bfv.Ciphertext
	ID         CipherID
}

//RetrieveQuery query for a ciphertext represented by ID1 to be switched under publickey
type RetrieveQuery struct {
	PublicKey *bfv.PublicKey
	ID        CipherID
}

type RetrieveRequest RetrieveQuery

type RetrieveBroadcast SwitchingParameters

//RetrieveReply contains the ciphertext switched under the key requested.
type RetrieveReply struct {
	ID         CipherID
	Ciphertext *bfv.Ciphertext
	valid      bool
}

type RetrieveResponse RetrieveReply

// Client asks to sum ciphertexts ID1 and ID2.
type SumQuery struct {
	ID1 CipherID
	ID2 CipherID
}

// Server further assigns an ID to the query
type SumRequestID uuid.UUID

// Message sent by server to root.
type SumRequest struct {
	SumRequestID
	*SumQuery
}

// Root answers with the same SumRequestID, the CipherID of the new ciphertext,
// and a flag indicating whether the operation succeeded.
type SumReply struct {
	SumRequestID
	NewID CipherID
	valid bool
}

// Client asks to multiply ID1 and ID2
type MultiplyQuery struct {
	ID1 CipherID
	ID2 CipherID
}

type MultiplyRequestID uuid.UUID

// Message sent by server to root.
type MultiplyRequest struct {
	MultiplyRequestID
	*MultiplyQuery
}

// Root answers with the same SumRequestID, the CipherID of the new ciphertext,
// and a flag indicating whether the operation succeeded.
type MultiplyReply struct {
	MultiplyRequestID
	NewID CipherID
	valid bool
}

// Client asks to relinearise the given CipherID
type RelinQuery struct {
	ID CipherID
}

type RelinRequest RelinQuery

//RefreshQuery query for ID1 to be refreshed.
type RefreshQuery struct {
	ID CipherID
}

type RefreshRequest RefreshQuery

type RefreshBroadcast struct {
	ct *bfv.Ciphertext
}

type RefreshReply struct {
	ID    CipherID
	ct    *bfv.Ciphertext
	valid bool
}

type RefreshResponse RefreshReply

type RotationQuery struct {
	ID     CipherID
	K      uint64
	RotIdx int
}

type RotationRequestID uuid.UUID

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
