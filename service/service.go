package service

import (
	"errors"
	"github.com/ldsec/lattigo/bfv"
	"github.com/ldsec/lattigo/dbfv"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
	"sync"
)

type Service struct {
	*onet.ServiceProcessor

	sessionsLock sync.RWMutex
	sessions     map[SessionID]*Session

	// The CreateSession and CloseSession queries entail a broadcast from the root. The root waits for answers here
	// TODO:  migrate to protocol
	createSessionBroadcastAnswers map[CreateSessionRequestID]chan *CreateSessionBroadcastAnswer
	closeSessionBroadcastAnswers  map[CloseSessionRequestID]chan *CloseSessionBroadcastAnswer

	// Synchronisation point between HandleCreateSessionQuery and processCreateSessionReply
	createSessionRepLock sync.RWMutex
	createSessionReplies map[CreateSessionRequestID]chan *CreateSessionReply
	// Synchronisation point between HandleCloseSessionQuery and processCloseSessionReply
	closeSessionRepLock sync.RWMutex
	closeSessionReplies map[CloseSessionRequestID]chan *CloseSessionReply
}

// Service is the service of lattigoSMC - allows to compute the different HE operations
type Session struct {
	SessionID SessionID

	Roster *onet.Roster

	// These variables are set upon construction.
	Params  *bfv.Parameters
	skShard *bfv.SecretKey
	// These variables have to be set via an explicit Query.
	pubKeyLock      sync.RWMutex
	MasterPublicKey *bfv.PublicKey
	rotKeyLock      sync.RWMutex
	rotationKey     *bfv.RotationKeys
	evalKeyLock     sync.RWMutex
	evalKey         *bfv.EvaluationKey

	// Stores ciphertexts.
	databaseLock sync.RWMutex
	database     map[CipherID]*bfv.Ciphertext
	// Stores additive shares.
	sharesLock sync.RWMutex
	shares     map[SharesID]*dbfv.AdditiveShare

	// Synchronisation point between HandleQuery and the corresponding processReply
	genPubKeyRepLock   sync.RWMutex
	genPubKeyReplies   map[GenPubKeyRequestID]chan *GenPubKeyReply
	genEvalKeyRepLock  sync.RWMutex
	genEvalKeyReplies  map[GenEvalKeyRequestID]chan *GenEvalKeyReply
	genRotKeyRepLock   sync.RWMutex
	genRotKeyReplies   map[GenRotKeyRequestID]chan *GenRotKeyReply
	keyRepLock         sync.RWMutex
	keyReplies         map[KeyRequestID]chan *KeyReply
	storeRepLock       sync.RWMutex
	storeReplies       map[StoreRequestID]chan *StoreReply
	sumRepLock         sync.RWMutex
	sumReplies         map[SumRequestID]chan *SumReply
	multiplyRepLock    sync.RWMutex
	multiplyReplies    map[MultiplyRequestID]chan *MultiplyReply
	relinRepLock       sync.RWMutex
	relinReplies       map[RelinRequestID]chan *RelinReply
	rotationRepLock    sync.RWMutex
	rotationReplies    map[RotationRequestID]chan *RotationReply
	retrieveRepLock    sync.RWMutex
	retrieveReplies    map[RetrieveRequestID]chan *RetrieveReply
	refreshRepLock     sync.RWMutex
	refreshReplies     map[RefreshRequestID]chan *RefreshReply
	encToSharesRepLock sync.RWMutex
	encToSharesReplies map[EncToSharesRequestID]chan *EncToSharesReply
	sharesToEncRepLock sync.RWMutex
	sharesToEncReplies map[SharesToEncRequestID]chan *SharesToEncReply
}

const ServiceName = "LattigoSMC"

// Registers the LattigoSMC service to the onet library
func init() {
	_, err := onet.RegisterNewService(ServiceName, NewService)
	if err != nil {
		log.Error("Could not register the service")
		panic(err)
	}
}

// Constructor of a service
func NewService(c *onet.Context) (onet.Service, error) {
	log.Lvl1(c.ServerIdentity(), "LattigoSMCService constructor started")

	smcService := &Service{
		ServiceProcessor: onet.NewServiceProcessor(c),

		// No need to initialise sessionsLock
		sessions: make(map[SessionID]*Session),

		createSessionBroadcastAnswers: make(map[CreateSessionRequestID]chan *CreateSessionBroadcastAnswer),
		closeSessionBroadcastAnswers:  make(map[CloseSessionRequestID]chan *CloseSessionBroadcastAnswer),

		createSessionReplies: make(map[CreateSessionRequestID]chan *CreateSessionReply),
		closeSessionReplies:  make(map[CloseSessionRequestID]chan *CloseSessionReply),
	}

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

// Constructor of a session. Already requires roster and bfv parameters.
func (smc *Service) NewSession(id SessionID, roster *onet.Roster, params *bfv.Parameters) *Session {
	log.Lvl1(smc.ServerIdentity(), "Session constructor started")

	session := &Session{
		SessionID: id,

		Roster: roster,

		Params: params,

		// No need to initialise pubKeyLock, rotKeyLock, and evalKeyLock

		// No need to initialise databaseLock
		database: make(map[CipherID]*bfv.Ciphertext),
		// No need to initialise sharesLock
		shares: make(map[SharesID]*dbfv.AdditiveShare),

		// No need to initialise locks
		genPubKeyReplies:   make(map[GenPubKeyRequestID]chan *GenPubKeyReply),
		genEvalKeyReplies:  make(map[GenEvalKeyRequestID]chan *GenEvalKeyReply),
		genRotKeyReplies:   make(map[GenRotKeyRequestID]chan *GenRotKeyReply),
		keyReplies:         make(map[KeyRequestID]chan *KeyReply),
		storeReplies:       make(map[StoreRequestID]chan *StoreReply),
		sumReplies:         make(map[SumRequestID]chan *SumReply),
		multiplyReplies:    make(map[MultiplyRequestID]chan *MultiplyReply),
		relinReplies:       make(map[RelinRequestID]chan *RelinReply),
		rotationReplies:    make(map[RotationRequestID]chan *RotationReply),
		retrieveReplies:    make(map[RetrieveRequestID]chan *RetrieveReply),
		refreshReplies:     make(map[RefreshRequestID]chan *RefreshReply),
		encToSharesReplies: make(map[EncToSharesRequestID]chan *EncToSharesReply),
		sharesToEncReplies: make(map[SharesToEncRequestID]chan *SharesToEncReply),
	}

	keygen := bfv.NewKeyGenerator(params)
	session.skShard = keygen.GenSecretKey()

	return session
}

// Registers in smcService handlers - of the form func(msg interface{})(ret interface{}, err error) -
// for every possible type of client request, implicitly identified by the type of msg.
func registerClientQueryHandlers(smcService *Service) error {
	if err := smcService.RegisterHandler(smcService.HandleCreateSessionQuery); err != nil {
		return errors.New("Couldn't register HandleCreateSessionQuery: " + err.Error())
	}
	if err := smcService.RegisterHandler(smcService.HandleCloseSessionQuery); err != nil {
		return errors.New("Couldn't register HandleCloseSessionQuery: " + err.Error())
	}
	if err := smcService.RegisterHandler(smcService.HandleGenPubKeyQuery); err != nil {
		return errors.New("Couldn't register HandleGenPubKeyQuery: " + err.Error())
	}
	if err := smcService.RegisterHandler(smcService.HandleGenEvalKeyQuery); err != nil {
		return errors.New("Couldn't register HandleGenEvalKeyQuery: " + err.Error())
	}
	if err := smcService.RegisterHandler(smcService.HandleGenRotKeyQuery); err != nil {
		return errors.New("Couldn't register HandleGenRotKeyQuery: " + err.Error())
	}
	if err := smcService.RegisterHandler(smcService.HandleStoreQuery); err != nil {
		return errors.New("Couldn't register HandleStoreQuery: " + err.Error())
	}
	if err := smcService.RegisterHandler(smcService.HandleSumQuery); err != nil {
		return errors.New("Couldn't register HandleSumQuery: " + err.Error())
	}
	if err := smcService.RegisterHandler(smcService.HandleMultiplyQuery); err != nil {
		return errors.New("Couldn't register HandleMultiplyQuery: " + err.Error())
	}
	if err := smcService.RegisterHandler(smcService.HandleCreateSessionQuery); err != nil {
		return errors.New("Couldn't register HandleCreateSessionQuery: " + err.Error())
	}
	if err := smcService.RegisterHandler(smcService.HandleRetrieveQuery); err != nil {
		return errors.New("Couldn't register HandleRetrieveQuery: " + err.Error())
	}
	if err := smcService.RegisterHandler(smcService.HandleKeyQuery); err != nil {
		return errors.New("Couldn't register HandleKeyQuery: " + err.Error())
	}
	if err := smcService.RegisterHandler(smcService.HandleRelinearisationQuery); err != nil {
		return errors.New("Couldn't register HandleRelinearizationquery: " + err.Error())
	}
	if err := smcService.RegisterHandler(smcService.HandleRefreshQuery); err != nil {
		return errors.New("Couldn't register HandleRefreshQuery: " + err.Error())
	}
	if err := smcService.RegisterHandler(smcService.HandleRotationQuery); err != nil {
		return errors.New("Couldn't register HandleRotationQuery: " + err.Error())
	}
	if err := smcService.RegisterHandler(smcService.HandleEncToSharesQuery); err != nil {
		return errors.New("Couldn't register HandleEncToSharesQuery: " + err.Error())
	}
	if err := smcService.RegisterHandler(smcService.HandleSharesToEncQuery); err != nil {
		return errors.New("Couldn't register HandleSharesToEncQuery: " + err.Error())
	}

	return nil
}

// Registers smcService to the underlying onet.Context as a processor for all the possible types of messages
// received by another server (every client request is forwarded to the root, so every query entails some
// server-root interaction). Upon reception of one of these messages, the method Process will be invoked.
func registerServerMsgHandler(c *onet.Context, smcService *Service) {
	// Create Session
	c.RegisterProcessor(smcService, msgTypes.msgCreateSessionRequest)
	c.RegisterProcessor(smcService, msgTypes.msgCreateSessionBroadcast)
	c.RegisterProcessor(smcService, msgTypes.msgCreateSessionBroadcastAnswer)
	c.RegisterProcessor(smcService, msgTypes.msgCreateSessionReply)

	// Close Session
	c.RegisterProcessor(smcService, msgTypes.msgCloseSessionRequest)
	c.RegisterProcessor(smcService, msgTypes.msgCloseSessionBroadcast)
	c.RegisterProcessor(smcService, msgTypes.msgCloseSessionBroadcastAnswer)
	c.RegisterProcessor(smcService, msgTypes.msgCloseSessionReply)

	// Generate Public Key
	c.RegisterProcessor(smcService, msgTypes.msgGenPubKeyRequest)
	c.RegisterProcessor(smcService, msgTypes.msgGenPubKeyReply)

	// Generate Evaluation Key
	c.RegisterProcessor(smcService, msgTypes.msgGenEvalKeyRequest)
	c.RegisterProcessor(smcService, msgTypes.msgGenEvalKeyReply)

	// Generate Rotation Key
	c.RegisterProcessor(smcService, msgTypes.msgGenRotKeyRequest)
	c.RegisterProcessor(smcService, msgTypes.msgGenRotKeyReply)

	// Key
	c.RegisterProcessor(smcService, msgTypes.msgKeyRequest)
	c.RegisterProcessor(smcService, msgTypes.msgKeyReply)

	// Store
	c.RegisterProcessor(smcService, msgTypes.msgStoreRequest)
	c.RegisterProcessor(smcService, msgTypes.msgStoreReply)

	// Retrieve
	c.RegisterProcessor(smcService, msgTypes.msgRetrieveRequest)
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
	c.RegisterProcessor(smcService, msgTypes.msgRefreshReply)

	// Rotation
	c.RegisterProcessor(smcService, msgTypes.msgRotationRequest)
	c.RegisterProcessor(smcService, msgTypes.msgRotationReply)

	// Encryption to shares
	c.RegisterProcessor(smcService, msgTypes.msgEncToSharesRequest)
	c.RegisterProcessor(smcService, msgTypes.msgEncToSharesReply)

	// Shares to encryption
	c.RegisterProcessor(smcService, msgTypes.msgSharesToEncRequest)
	c.RegisterProcessor(smcService, msgTypes.msgSharesToEncReply)
}

// Process processes messages from servers. It is called by the onet library upon reception of any of
// the messages registered in registerServerMsgHandler. For this reason, the Process method
// is bound to be a giant if-else-if, which "manually" dispatches based on the message type.
func (smc *Service) Process(msg *network.Envelope) {
	// Create Session
	if msg.MsgType.Equal(msgTypes.msgCreateSessionRequest) {
		smc.processCreateSessionRequest(msg)
		return
	}
	if msg.MsgType.Equal(msgTypes.msgCreateSessionBroadcast) {
		smc.processCreateSessionBroadcast(msg)
		return
	}
	if msg.MsgType.Equal(msgTypes.msgCreateSessionBroadcastAnswer) {
		smc.processCreateSessionBroadcastAnswer(msg)
		return
	}
	if msg.MsgType.Equal(msgTypes.msgCreateSessionReply) {
		smc.processCreateSessionReply(msg)
		return
	}

	// Close Session
	if msg.MsgType.Equal(msgTypes.msgCloseSessionRequest) {
		smc.processCloseSessionRequest(msg)
		return
	}
	if msg.MsgType.Equal(msgTypes.msgCloseSessionBroadcast) {
		smc.processCloseSessionBroadcast(msg)
		return
	}
	if msg.MsgType.Equal(msgTypes.msgCloseSessionBroadcastAnswer) {
		smc.processCloseSessionBroadcastAnswer(msg)
		return
	}
	if msg.MsgType.Equal(msgTypes.msgCloseSessionReply) {
		smc.processCloseSessionReply(msg)
		return
	}

	// Generate Public Key
	if msg.MsgType.Equal(msgTypes.msgGenPubKeyRequest) {
		smc.processGenPubKeyRequest(msg)
		return
	}
	if msg.MsgType.Equal(msgTypes.msgGenPubKeyReply) {
		smc.processGenPubKeyReply(msg)
		return
	}

	// Generate Evaluation Key
	if msg.MsgType.Equal(msgTypes.msgGenEvalKeyRequest) {
		smc.processGenEvalKeyRequest(msg)
		return
	}
	if msg.MsgType.Equal(msgTypes.msgGenEvalKeyReply) {
		smc.processGenEvalKeyReply(msg)
		return
	}

	// Generate Rotation Key
	if msg.MsgType.Equal(msgTypes.msgGenRotKeyRequest) {
		smc.processGenRotKeyRequest(msg)
		return
	}
	if msg.MsgType.Equal(msgTypes.msgGenRotKeyReply) {
		smc.processGenRotKeyReply(msg)
		return
	}

	// Key
	if msg.MsgType.Equal(msgTypes.msgKeyRequest) {
		smc.processKeyRequest(msg)
		return
	}
	if msg.MsgType.Equal(msgTypes.msgKeyReply) {
		smc.processKeyReply(msg)
		return
	}

	// Store
	if msg.MsgType.Equal(msgTypes.msgStoreRequest) {
		smc.processStoreRequest(msg)
		return
	}
	if msg.MsgType.Equal(msgTypes.msgStoreReply) {
		smc.processStoreReply(msg)
		return
	}

	// Retrieve
	if msg.MsgType.Equal(msgTypes.msgRetrieveRequest) {
		smc.processRetrieveRequest(msg)
		return
	} /*
		if msg.MsgType.Equal(msgTypes.msgRetrieveBroadcast) {
			smc.processRetrieveBroadcast(msg)
			return
		}*/
	if msg.MsgType.Equal(msgTypes.msgRetrieveReply) {
		smc.processRetrieveReply(msg)
		return
	}

	// Sum
	if msg.MsgType.Equal(msgTypes.msgSumRequest) {
		smc.processSumRequest(msg)
		return
	}
	if msg.MsgType.Equal(msgTypes.msgSumReply) {
		smc.processSumReply(msg)
		return
	}

	// Multiply
	if msg.MsgType.Equal(msgTypes.msgMultiplyRequest) {
		smc.processMultiplyRequest(msg)
		return
	}
	if msg.MsgType.Equal(msgTypes.msgMultiplyReply) {
		smc.processMultiplyReply(msg)
		return
	}

	// Relinearise
	if msg.MsgType.Equal(msgTypes.msgRelinRequest) {
		smc.processRelinRequest(msg)
		return
	}
	if msg.MsgType.Equal(msgTypes.msgRelinReply) {
		smc.processRelinReply(msg)
		return
	}

	// Refresh
	if msg.MsgType.Equal(msgTypes.msgRefreshRequest) {
		smc.processRefreshRequest(msg)
		return
	} /*
		if msg.MsgType.Equal(msgTypes.msgRefreshBroadcast) {
			smc.processRefreshBroadcast(msg)
			return
		}*/
	if msg.MsgType.Equal(msgTypes.msgRefreshReply) {
		smc.processRefreshReply(msg)
		return
	}

	// Rotation
	if msg.MsgType.Equal(msgTypes.msgRotationRequest) {
		smc.processRotationRequest(msg)
		return
	}
	if msg.MsgType.Equal(msgTypes.msgRotationReply) {
		smc.processRotationReply(msg)
		return
	}

	// Encryption to shares
	if msg.MsgType.Equal(msgTypes.msgEncToSharesRequest) {
		smc.processEncToSharesRequest(msg)
		return
	} /*
		if msg.MsgType.Equal(msgTypes.msgEncToSharesBroadcast) {
			smc.processEncToSharesBroadcast(msg)
			return
		}*/
	if msg.MsgType.Equal(msgTypes.msgEncToSharesReply) {
		smc.processEncToSharesReply(msg)
		return
	}

	// Shares to encryption
	if msg.MsgType.Equal(msgTypes.msgSharesToEncRequest) {
		smc.processSharesToEncRequest(msg)
		return
	} /*
		if msg.MsgType.Equal(msgTypes.msgEncToSharesBroadcast) {
			smc.processSharesToEncBroadcast(msg)
			return
		}*/
	if msg.MsgType.Equal(msgTypes.msgSharesToEncReply) {
		smc.processSharesToEncReply(msg)
		return
	}

	log.Error("Unknown message type:", msg.MsgType)
}
