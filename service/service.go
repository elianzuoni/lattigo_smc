package service

import (
	"errors"
	"github.com/ldsec/lattigo/bfv"
	"github.com/ldsec/lattigo/dbfv"
	"github.com/ldsec/lattigo/ring"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
)

type Service struct {
	*onet.ServiceProcessor

	// TODO: RWMutex to manage concurrent queries
	sessions map[SessionID]*Session

	// The CreateSession and CloseSession queries entail a broadcast from the root. The root waits for answers here
	// TODO:  migrate to protocol
	createSessionBroadcastAnswers map[CreateSessionRequestID]chan *CreateSessionBroadcastAnswer
	closeSessionBroadcastAnswers  map[CloseSessionRequestID]chan *CloseSessionBroadcastAnswer

	// Synchronisation point between HandleCreateSessionQuery and the corresponding processCreateSessionReply
	createSessionReplies map[CreateSessionRequestID]chan *CreateSessionReply
	// Synchronisation point between HandleCloseSessionQuery and the corresponding processCloseSessionReply
	closeSessionReplies map[CloseSessionRequestID]chan *CloseSessionReply
}

// Service is the service of lattigoSMC - allows to compute the different HE operations
type Session struct {
	SessionID SessionID

	Roster *onet.Roster

	// General bfv parameters
	Params          *bfv.Parameters
	skShard         *bfv.SecretKey
	MasterPublicKey *bfv.PublicKey
	rotationKey     *bfv.RotationKeys
	evalKey         *bfv.EvaluationKey

	// CRP generators for PublicKey and Ciphertext
	// TODO: if we can have concurrent queries, we should either lock these, or choose CRP at root and propagate it
	crpGen       *ring.CRPGenerator
	cipherCRPgen *ring.CRPGenerator

	// Rotation parameters
	// TODO: needed? Isn't the rotation key sufficient?
	rotIdx int
	k      uint64

	// Stores ciphertexts. Only used at the root.
	database map[CipherID]*bfv.Ciphertext
	// Stores additive shares. Used at every node.
	shares map[CipherID]*dbfv.AdditiveShare

	/*
		// Synchronisation points between protocol factories and their corresponding
		// processBroadcast (that sets up the variables needed).
		// All queries use, for example, the secret key shard, but only CKG and EKG wait
		// until they become available. // TODO: is this fair?
		waitCKG sync.Mutex // CKG protocol factory waits here to read variables
		waitEKG sync.Mutex // EKG protocol factory waits here to read variables
		waitRKG sync.Mutex // RKG protocol factory waits here to read variables
		// TODO: should these be maps as well?
		refreshParams     map[RefreshRequestID]chan *bfv.Ciphertext   // Refresh protocol factory reads variables from here
		switchingParams   map[RetrieveRequestID]chan *SwitchingParameters // CKS protocol factory reads variables from here
		encToSharesParams map[EncToSharesRequestID]chan *E2SParameters    // E2S protocol factory reads variables from here
		sharesToEncParams map[SharesToEncRequestID]chan *S2EParameters    // S2E protocol factory reads variables from here
	*/

	// Synchronisation point between HandleQuery and the corresponding processReply
	genPubKeyReplies   map[GenPubKeyRequestID]chan *GenPubKeyReply
	genEvalKeyReplies  map[GenEvalKeyRequestID]chan *GenEvalKeyReply
	genRotKeyReplies   map[GenRotKeyRequestID]chan *GenRotKeyReply
	keyReplies         map[KeyRequestID]chan *KeyReply
	storeReplies       map[StoreRequestID]chan *StoreReply
	sumReplies         map[SumRequestID]chan *SumReply
	multiplyReplies    map[MultiplyRequestID]chan *MultiplyReply
	relinReplies       map[RelinRequestID]chan *RelinReply
	rotationReplies    map[RotationRequestID]chan *RotationReply
	retrieveReplies    map[RetrieveRequestID]chan *RetrieveReply
	refreshReplies     map[RefreshRequestID]chan *RefreshReply
	encToSharesReplies map[EncToSharesRequestID]chan *EncToSharesReply
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
		sessions:         make(map[SessionID]*Session),

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

// Constructor of a session. Already requires roster, bfv parameters, and seed for CRP generator.
func (smc *Service) NewSession(id SessionID, roster *onet.Roster, params *bfv.Parameters, seed []byte) *Session {
	log.Lvl1(smc.ServerIdentity(), "Session constructor started")

	session := &Session{
		SessionID: id,

		Roster: roster,

		Params: params,

		crpGen:       dbfv.NewCRPGenerator(params, seed),
		cipherCRPgen: dbfv.NewCipherCRPGenerator(params, seed),

		database: make(map[CipherID]*bfv.Ciphertext),
		shares:   make(map[CipherID]*dbfv.AdditiveShare),

		/*
			// No need to initialise Locks
			refreshParams:     make(map[RefreshRequestID]chan *bfv.Ciphertext),
			switchingParams:   make(map[RetrieveRequestID]chan *SwitchingParameters),
			encToSharesParams: make(map[EncToSharesRequestID]chan *E2SParameters),
			sharesToEncParams: make(map[SharesToEncRequestID]chan *S2EParameters),
		*/

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

	/*
		// The zero value of a Mutex is an unlocked one
		session.waitCKG.Lock()
		session.waitEKG.Lock()
		session.waitRKG.Lock()
	*/

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
	/*c.RegisterProcessor(smcService, msgTypes.msgRetrieveBroadcast)*/
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
	/*c.RegisterProcessor(smcService, msgTypes.msgRefreshBroadcast)*/
	c.RegisterProcessor(smcService, msgTypes.msgRefreshReply)

	// Rotation
	c.RegisterProcessor(smcService, msgTypes.msgRotationReply)
	c.RegisterProcessor(smcService, msgTypes.msgRotationReply)

	// Encryption to shares
	c.RegisterProcessor(smcService, msgTypes.msgEncToSharesRequest)
	/*c.RegisterProcessor(smcService, msgTypes.msgEncToSharesBroadcast)*/
	c.RegisterProcessor(smcService, msgTypes.msgEncToSharesReply)

	// Shares to encryption
	c.RegisterProcessor(smcService, msgTypes.msgSharesToEncRequest)
	/*c.RegisterProcessor(smcService, msgTypes.msgSharesToEncBroadcast)*/
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
		smc.processGenPubKeyRequest(msg)
		return
	}
	if msg.MsgType.Equal(msgTypes.msgGenRotKeyReply) {
		smc.processGenPubKeyReply(msg)
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
	if msg.MsgType.Equal(msgTypes.msgEncToSharesReply) {
		smc.processSharesToEncReply(msg)
		return
	}

	log.Error("Unknown message type:", msg.MsgType)
}
