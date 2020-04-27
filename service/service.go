package service

import (
	"errors"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
	"lattigo-smc/service/messages"
	"lattigo-smc/service/session"
	"sync"
)

type Service struct {
	*onet.ServiceProcessor

	sessions *session.SessionStore

	// Synchronisation point between HandleCreateSessionQuery and processCreateSessionReply
	createSessionRepLock sync.RWMutex
	createSessionReplies map[messages.CreateSessionRequestID]chan *messages.CreateSessionReply
	// Synchronisation point between HandleCloseSessionQuery and processCloseSessionReply
	closeSessionRepLock sync.RWMutex
	closeSessionReplies map[messages.CloseSessionRequestID]chan *messages.CloseSessionReply
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

		sessions: session.NewSessionStore(),

		createSessionReplies: make(map[messages.CreateSessionRequestID]chan *messages.CreateSessionReply),
		closeSessionReplies:  make(map[messages.CloseSessionRequestID]chan *messages.CloseSessionReply),
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
	c.RegisterProcessor(smcService, messages.MsgTypes.MsgCreateSessionRequest)
	c.RegisterProcessor(smcService, messages.MsgTypes.MsgCreateSessionReply)

	// Close Session
	c.RegisterProcessor(smcService, messages.MsgTypes.MsgCloseSessionRequest)
	c.RegisterProcessor(smcService, messages.MsgTypes.MsgCloseSessionReply)

	// Generate Public Key
	c.RegisterProcessor(smcService, messages.MsgTypes.MsgGenPubKeyRequest)
	c.RegisterProcessor(smcService, messages.MsgTypes.MsgGenPubKeyReply)

	// Generate Evaluation Key
	c.RegisterProcessor(smcService, messages.MsgTypes.MsgGenEvalKeyRequest)
	c.RegisterProcessor(smcService, messages.MsgTypes.MsgGenEvalKeyReply)

	// Generate Rotation Key
	c.RegisterProcessor(smcService, messages.MsgTypes.MsgGenRotKeyRequest)
	c.RegisterProcessor(smcService, messages.MsgTypes.MsgGenRotKeyReply)

	// Key
	c.RegisterProcessor(smcService, messages.MsgTypes.MsgKeyRequest)
	c.RegisterProcessor(smcService, messages.MsgTypes.MsgKeyReply)

	// Store
	c.RegisterProcessor(smcService, messages.MsgTypes.MsgStoreRequest)
	c.RegisterProcessor(smcService, messages.MsgTypes.MsgStoreReply)

	// Retrieve
	c.RegisterProcessor(smcService, messages.MsgTypes.MsgRetrieveRequest)
	c.RegisterProcessor(smcService, messages.MsgTypes.MsgRetrieveReply)

	// Sum
	c.RegisterProcessor(smcService, messages.MsgTypes.MsgSumRequest)
	c.RegisterProcessor(smcService, messages.MsgTypes.MsgSumReply)

	// Multiply
	c.RegisterProcessor(smcService, messages.MsgTypes.MsgMultiplyRequest)
	c.RegisterProcessor(smcService, messages.MsgTypes.MsgMultiplyReply)

	// Relinearise
	c.RegisterProcessor(smcService, messages.MsgTypes.MsgRelinRequest)
	c.RegisterProcessor(smcService, messages.MsgTypes.MsgRelinReply)

	// Refresh
	c.RegisterProcessor(smcService, messages.MsgTypes.MsgRefreshRequest)
	c.RegisterProcessor(smcService, messages.MsgTypes.MsgRefreshReply)

	// Rotation
	c.RegisterProcessor(smcService, messages.MsgTypes.MsgRotationRequest)
	c.RegisterProcessor(smcService, messages.MsgTypes.MsgRotationReply)

	// Encryption to shares
	c.RegisterProcessor(smcService, messages.MsgTypes.MsgEncToSharesRequest)
	c.RegisterProcessor(smcService, messages.MsgTypes.MsgEncToSharesReply)

	// Shares to encryption
	c.RegisterProcessor(smcService, messages.MsgTypes.MsgSharesToEncRequest)
	c.RegisterProcessor(smcService, messages.MsgTypes.MsgSharesToEncReply)
}

// Process processes messages from servers. It is called by the onet library upon reception of any of
// the messages registered in registerServerMsgHandler. For this reason, the Process method
// is bound to be a giant if-else-if, which "manually" dispatches based on the message type.
func (smc *Service) Process(msg *network.Envelope) {
	// Create Session
	if msg.MsgType.Equal(messages.MsgTypes.MsgCreateSessionRequest) {
		smc.processCreateSessionRequest(msg)
		return
	}
	if msg.MsgType.Equal(messages.MsgTypes.MsgCreateSessionReply) {
		smc.processCreateSessionReply(msg)
		return
	}

	// Close Session
	if msg.MsgType.Equal(messages.MsgTypes.MsgCloseSessionRequest) {
		smc.processCloseSessionRequest(msg)
		return
	}
	if msg.MsgType.Equal(messages.MsgTypes.MsgCloseSessionReply) {
		smc.processCloseSessionReply(msg)
		return
	}

	// Generate Public Key
	if msg.MsgType.Equal(messages.MsgTypes.MsgGenPubKeyRequest) {
		smc.processGenPubKeyRequest(msg)
		return
	}
	if msg.MsgType.Equal(messages.MsgTypes.MsgGenPubKeyReply) {
		smc.processGenPubKeyReply(msg)
		return
	}

	// Generate Evaluation Key
	if msg.MsgType.Equal(messages.MsgTypes.MsgGenEvalKeyRequest) {
		smc.processGenEvalKeyRequest(msg)
		return
	}
	if msg.MsgType.Equal(messages.MsgTypes.MsgGenEvalKeyReply) {
		smc.processGenEvalKeyReply(msg)
		return
	}

	// Generate Rotation Key
	if msg.MsgType.Equal(messages.MsgTypes.MsgGenRotKeyRequest) {
		smc.processGenRotKeyRequest(msg)
		return
	}
	if msg.MsgType.Equal(messages.MsgTypes.MsgGenRotKeyReply) {
		smc.processGenRotKeyReply(msg)
		return
	}

	// Key
	if msg.MsgType.Equal(messages.MsgTypes.MsgKeyRequest) {
		smc.processKeyRequest(msg)
		return
	}
	if msg.MsgType.Equal(messages.MsgTypes.MsgKeyReply) {
		smc.processKeyReply(msg)
		return
	}

	// Store
	if msg.MsgType.Equal(messages.MsgTypes.MsgStoreRequest) {
		smc.processStoreRequest(msg)
		return
	}
	if msg.MsgType.Equal(messages.MsgTypes.MsgStoreReply) {
		smc.processStoreReply(msg)
		return
	}

	// Retrieve
	if msg.MsgType.Equal(messages.MsgTypes.MsgRetrieveRequest) {
		smc.processRetrieveRequest(msg)
		return
	}
	if msg.MsgType.Equal(messages.MsgTypes.MsgRetrieveReply) {
		smc.processRetrieveReply(msg)
		return
	}

	// Sum
	if msg.MsgType.Equal(messages.MsgTypes.MsgSumRequest) {
		smc.processSumRequest(msg)
		return
	}
	if msg.MsgType.Equal(messages.MsgTypes.MsgSumReply) {
		smc.processSumReply(msg)
		return
	}

	// Multiply
	if msg.MsgType.Equal(messages.MsgTypes.MsgMultiplyRequest) {
		smc.processMultiplyRequest(msg)
		return
	}
	if msg.MsgType.Equal(messages.MsgTypes.MsgMultiplyReply) {
		smc.processMultiplyReply(msg)
		return
	}

	// Relinearise
	if msg.MsgType.Equal(messages.MsgTypes.MsgRelinRequest) {
		smc.processRelinRequest(msg)
		return
	}
	if msg.MsgType.Equal(messages.MsgTypes.MsgRelinReply) {
		smc.processRelinReply(msg)
		return
	}

	// Refresh
	if msg.MsgType.Equal(messages.MsgTypes.MsgRefreshRequest) {
		smc.processRefreshRequest(msg)
		return
	}
	if msg.MsgType.Equal(messages.MsgTypes.MsgRefreshReply) {
		smc.processRefreshReply(msg)
		return
	}

	// Rotation
	if msg.MsgType.Equal(messages.MsgTypes.MsgRotationRequest) {
		smc.processRotationRequest(msg)
		return
	}
	if msg.MsgType.Equal(messages.MsgTypes.MsgRotationReply) {
		smc.processRotationReply(msg)
		return
	}

	// Encryption to shares
	if msg.MsgType.Equal(messages.MsgTypes.MsgEncToSharesRequest) {
		smc.processEncToSharesRequest(msg)
		return
	}
	if msg.MsgType.Equal(messages.MsgTypes.MsgEncToSharesReply) {
		smc.processEncToSharesReply(msg)
		return
	}

	// Shares to encryption
	if msg.MsgType.Equal(messages.MsgTypes.MsgSharesToEncRequest) {
		smc.processSharesToEncRequest(msg)
		return
	}
	if msg.MsgType.Equal(messages.MsgTypes.MsgSharesToEncReply) {
		smc.processSharesToEncReply(msg)
		return
	}

	log.Error("Unknown message type:", msg.MsgType)
}
