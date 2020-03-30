package service

import (
	"errors"
	"github.com/ldsec/lattigo/bfv"
	"github.com/ldsec/lattigo/ring"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
	"sync"
)

// Service is the service of lattigoSMC - allows to compute the different HE operations
type Service struct {
	*onet.ServiceProcessor
	onet.Roster

	// General bfv parameters
	MasterPublicKey *bfv.PublicKey
	skShard         *bfv.SecretKey
	partialPk       *bfv.PublicKey
	rotationKey     *bfv.RotationKeys
	evalKey         *bfv.EvaluationKey
	Params          *bfv.Parameters

	// Rotation parameters
	rotIdx int
	k      uint64

	// CRP generators for PublicKey and Ciphertext
	crpGen       *ring.CRPGenerator
	cipherCRPgen *ring.CRPGenerator

	// Flags indicating level of setup
	skSet            bool // Whether Params (and other fields like skShard) are set
	pubKeyGenerated  bool
	evalKeyGenerated bool
	rotParamsSet     bool // Whether rotIdx and k are set
	rotKeyGenerated  bool

	// Stores ciphertexts. Only used at the root.
	database map[CipherID]*bfv.Ciphertext

	// Synchronisation structures for protocol factories
	waitCKG sync.Mutex // CKG protocol factory waits here to read variables
	waitEKG sync.Mutex // EKG protocol factory waits here to read variables
	waitRKG sync.Mutex // RKG protocol factory waits here to read variables
	// TODO: should these be maps as well?
	refreshParams       chan *bfv.Ciphertext      // Refresh protocol factory reads variables from here
	switchingParameters chan *SwitchingParameters // CKS protocol factory reads variables from here

	// Structures for synchronisation between HandleQuery and processReply
	setupReplies    map[SetupRequestID]chan *SetupReply
	keyReplies      map[KeyRequestID]chan *KeyReply
	storeReplies    map[StoreRequestID]chan *StoreReply
	sumReplies      map[SumRequestID]chan *SumReply
	multiplyReplies map[MultiplyRequestID]chan *MultiplyReply
	relinReplies    map[RelinRequestID]chan *RelinReply
	rotationReplies map[RotationRequestID]chan *RotationReply
	retrieveReplies map[RetrieveRequestID]chan *RetrieveReply
	refreshReplies  map[RefreshRequestID]chan *RefreshReply
}

type SwitchingParameters struct {
	*bfv.PublicKey
	*bfv.Ciphertext
}

const ServiceName = "LattigoSMC"

// Registers the LattigoSMC service to the onet library
func init() {
	_, err := onet.RegisterNewService(ServiceName, NewLattigoSMCService)
	if err != nil {
		log.Error("Could not register the service")
		panic(err)
	}
}

func NewLattigoSMCService(c *onet.Context) (onet.Service, error) {
	log.Lvl1(c.ServerIdentity(), "Starting LattigoSMC service")

	smcService := &Service{
		ServiceProcessor: onet.NewServiceProcessor(c),

		database: make(map[CipherID]*bfv.Ciphertext),

		// No need to initialise Locks
		refreshParams:       make(chan *bfv.Ciphertext),
		switchingParameters: make(chan *SwitchingParameters),

		setupReplies:    make(map[SetupRequestID]chan *SetupReply),
		keyReplies:      make(map[KeyRequestID]chan *KeyReply),
		storeReplies:    make(map[StoreRequestID]chan *StoreReply),
		sumReplies:      make(map[SumRequestID]chan *SumReply),
		multiplyReplies: make(map[MultiplyRequestID]chan *MultiplyReply),
		relinReplies:    make(map[RelinRequestID]chan *RelinReply),
		rotationReplies: make(map[RotationRequestID]chan *RotationReply),
		retrieveReplies: make(map[RetrieveRequestID]chan *RetrieveReply),
		refreshReplies:  make(map[RefreshRequestID]chan *RefreshReply),
	}

	// The zero value of a Mutex is an unlocked one
	smcService.waitCKG.Lock()
	smcService.waitEKG.Lock()
	smcService.waitRKG.Lock()

	// Registers the handlers for client requests.
	e := registerClientQueryHandlers(smcService)
	if e != nil {
		log.Error("Error registering handlers for client queries")
		return nil, e
	}
	// Registers the (unique) handler for server's messages.
	registerServerMsgHandler(c, smcService)

	return smcService, nil
}

// Registers in smcService handlers - of the form func(msg interface{})(ret interface{}, err error) -
// for every possible type of client request, implicitly identified by the type of msg.
func registerClientQueryHandlers(smcService *Service) error {
	if err := smcService.RegisterHandler(smcService.HandleStoreQuery); err != nil {
		return errors.New("Couldn't register HandleStoreQuery: " + err.Error())
	}
	if err := smcService.RegisterHandler(smcService.HandleSumQuery); err != nil {
		return errors.New("Couldn't register HandleSumQuery: " + err.Error())
	}
	if err := smcService.RegisterHandler(smcService.HandleMultiplyQuery); err != nil {
		return errors.New("Couldn't register HandleMultiplyQuery: " + err.Error())
	}
	if err := smcService.RegisterHandler(smcService.HandleSetupQuery); err != nil {
		return errors.New("Couldn't register HandleSetupQuery: " + err.Error())
	}
	if err := smcService.RegisterHandler(smcService.HandleRetrieveQuery); err != nil {
		return errors.New("Couldn't register HandleRetrieveQuery: " + err.Error())
	}
	if err := smcService.RegisterHandler(smcService.HandleKeyQuery); err != nil {
		return errors.New("Couldn't register HandleKeyQuery: " + err.Error())
	}
	if err := smcService.RegisterHandler(smcService.HandleRelinearisationQuery); err != nil {
		return errors.New("HandleRelinearizationquery: " + err.Error())
	}
	if err := smcService.RegisterHandler(smcService.HandleRefreshQuery); err != nil {
		return errors.New("Couldn't register HandleRefreshQuery: " + err.Error())
	}
	if err := smcService.RegisterHandler(smcService.HandleRotationQuery); err != nil {
		return errors.New("HandleRotationQuery: " + err.Error())
	}
	return nil
}

// Registers smcService to the underlying onet.Context as a processor for all the possible types of messages
// received by another server (every client request is forwarded to the root, so every query entails some
// server-to-server interaction). Upon reception of one of these messages, the method Process will be invoked.
func registerServerMsgHandler(c *onet.Context, smcService *Service) {
	// Setup
	c.RegisterProcessor(smcService, msgTypes.msgSetupRequest)
	c.RegisterProcessor(smcService, msgTypes.msgSetupBroadcast)
	c.RegisterProcessor(smcService, msgTypes.msgSetupReply)

	// Key
	c.RegisterProcessor(smcService, msgTypes.msgKeyRequest)
	c.RegisterProcessor(smcService, msgTypes.msgKeyReply)

	// Store
	c.RegisterProcessor(smcService, msgTypes.msgStoreRequest)
	c.RegisterProcessor(smcService, msgTypes.msgStoreReply)

	// Retrieve
	c.RegisterProcessor(smcService, msgTypes.msgRetrieveRequest)
	c.RegisterProcessor(smcService, msgTypes.msgRetrieveBroadcast)
	c.RegisterProcessor(smcService, msgTypes.msgRetrieveReply)

	// Sum
	c.RegisterProcessor(smcService, msgTypes.msgSumRequest)
	c.RegisterProcessor(smcService, msgTypes.msgSumReply)

	// Multiply
	c.RegisterProcessor(smcService, msgTypes.msgMultiplyRequest)
	c.RegisterProcessor(smcService, msgTypes.msgMultiplyReply)

	// Relinearise
	c.RegisterProcessor(smcService, msgTypes.msgRelinRequest)
	c.RegisterProcessor(smcService, msgTypes.msgRelinReply)

	// Refresh
	c.RegisterProcessor(smcService, msgTypes.msgRefreshRequest)
	c.RegisterProcessor(smcService, msgTypes.msgRefreshBroadcast)
	c.RegisterProcessor(smcService, msgTypes.msgRefreshReply)

	// Rotation
	c.RegisterProcessor(smcService, msgTypes.msgRotationReply)
	c.RegisterProcessor(smcService, msgTypes.msgRotationReply)
}

// Process processes messages from servers. It is called by the onet library upon reception of any of
// the messages registered in registerServerMsgHandler. For this reason, the Process method
// is bound to be a giant if-else-if, which "manually" dispatches based on the message type.
func (s *Service) Process(msg *network.Envelope) {
	// Setup
	if msg.MsgType.Equal(msgTypes.msgSetupRequest) {
		s.processSetupRequest(msg)
		return
	}
	if msg.MsgType.Equal(msgTypes.msgSetupBroadcast) {
		s.processSetupBroadcast(msg)
		return
	}
	if msg.MsgType.Equal(msgTypes.msgSetupReply) {
		s.processSetupReply(msg)
		return
	}

	// Key
	if msg.MsgType.Equal(msgTypes.msgKeyRequest) {
		s.processKeyRequest(msg)
		return
	}
	if msg.MsgType.Equal(msgTypes.msgKeyReply) {
		s.processKeyReply(msg)
		return
	}

	// Store
	if msg.MsgType.Equal(msgTypes.msgStoreRequest) {
		s.processStoreRequest(msg)
		return
	}
	if msg.MsgType.Equal(msgTypes.msgStoreReply) {
		s.processStoreReply(msg)
		return
	}

	// Retrieve
	if msg.MsgType.Equal(msgTypes.msgRetrieveRequest) {
		s.processRetrieveRequest(msg)
		return
	}
	if msg.MsgType.Equal(msgTypes.msgRetrieveBroadcast) {
		s.processRetrieveBroadcast(msg)
		return
	}
	if msg.MsgType.Equal(msgTypes.msgRetrieveReply) {
		s.processRetrieveReply(msg)
		return
	}

	// Sum
	if msg.MsgType.Equal(msgTypes.msgSumRequest) {
		s.processSumRequest(msg)
		return
	}
	if msg.MsgType.Equal(msgTypes.msgSumReply) {
		s.processSumReply(msg)
		return
	}

	// Multiply
	if msg.MsgType.Equal(msgTypes.msgMultiplyRequest) {
		s.processMultiplyRequest(msg)
		return
	}
	if msg.MsgType.Equal(msgTypes.msgMultiplyReply) {
		s.processMultiplyReply(msg)
		return
	}

	// Relinearise
	if msg.MsgType.Equal(msgTypes.msgRelinRequest) {
		s.processRelinRequest(msg)
		return
	}
	if msg.MsgType.Equal(msgTypes.msgRelinReply) {
		s.processRelinReply(msg)
		return
	}

	// Refresh
	if msg.MsgType.Equal(msgTypes.msgRefreshRequest) {
		s.processRefreshRequest(msg)
		return
	}
	if msg.MsgType.Equal(msgTypes.msgRefreshBroadcast) {
		s.processRefreshBroadcast(msg)
		return
	}
	if msg.MsgType.Equal(msgTypes.msgRefreshReply) {
		s.processRefreshReply(msg)
		return
	}

	// Rotation
	if msg.MsgType.Equal(msgTypes.msgRotationRequest) {
		s.processRotationRequest(msg)
		return
	}
	if msg.MsgType.Equal(msgTypes.msgRotationReply) {
		s.processRotationReply(msg)
		return
	}

	log.Error("Unknown message type:", msg.MsgType)
}
