package session

import (
	"errors"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
	"lattigo-smc/service/messages"
	"sync"
)

type Service struct {
	*onet.ServiceProcessor

	sessions *SessionStore

	// Synchronisation point between HandleCreateSessionQuery and processCreateSessionReply
	createSessionRepLock sync.RWMutex
	createSessionReplies map[messages.CreateSessionRequestID]chan *messages.CreateSessionReply
	// Synchronisation point between HandleCloseSessionQuery and processCloseSessionReply
	closeSessionRepLock sync.RWMutex
	closeSessionReplies map[messages.CloseSessionRequestID]chan *messages.CloseSessionReply
	// Synchronisation point between RetrieveRemoteCiphertext and processGetCipherReply
	getCipherRepLock sync.RWMutex
	getCipherReplies map[messages.GetCipherRequestID]chan *messages.GetCipherReply
}

const ServiceName = "SessionService"

// Registers the Session Service to the onet library
func init() {
	_, err := onet.RegisterNewService(ServiceName, NewService)
	if err != nil {
		log.Error("Could not register the service")
		panic(err)
	}
}

// Constructor of Session Service
func NewService(c *onet.Context) (onet.Service, error) {
	log.Lvl1(c.ServerIdentity(), "SessionService constructor started")

	serv := &Service{
		ServiceProcessor: onet.NewServiceProcessor(c),

		createSessionReplies: make(map[messages.CreateSessionRequestID]chan *messages.CreateSessionReply),
		closeSessionReplies:  make(map[messages.CloseSessionRequestID]chan *messages.CloseSessionReply),
		getCipherReplies:     make(map[messages.GetCipherRequestID]chan *messages.GetCipherReply),
	}

	// Create the SessionStore, indicating itself as the reference Service
	serv.sessions = NewSessionStore(serv)

	// Registers the handlers for client requests.
	e := registerClientQueryHandlers(serv)
	if e != nil {
		log.Error("Error registering handlers for client queries")
		return nil, e
	}
	// Registers the (unique) handler for server's messages.
	registerServerMsgHandler(c, serv)

	return serv, nil
}

// Registers in serv handlers - of the form func(msg interface{})(ret interface{}, err error) -
// for every possible type of client request, implicitly identified by the type of msg.
func registerClientQueryHandlers(serv *Service) error {
	if err := serv.RegisterHandler(serv.HandleCreateSessionQuery); err != nil {
		return errors.New("Couldn't register HandleCreateSessionQuery: " + err.Error())
	}
	if err := serv.RegisterHandler(serv.HandleCloseSessionQuery); err != nil {
		return errors.New("Couldn't register HandleCloseSessionQuery: " + err.Error())
	}
	if err := serv.RegisterHandler(serv.HandleGenPubKeyQuery); err != nil {
		return errors.New("Couldn't register HandleGenPubKeyQuery: " + err.Error())
	}
	if err := serv.RegisterHandler(serv.HandleGenEvalKeyQuery); err != nil {
		return errors.New("Couldn't register HandleGenEvalKeyQuery: " + err.Error())
	}
	if err := serv.RegisterHandler(serv.HandleGenRotKeyQuery); err != nil {
		return errors.New("Couldn't register HandleGenRotKeyQuery: " + err.Error())
	}
	if err := serv.RegisterHandler(serv.HandleStoreQuery); err != nil {
		return errors.New("Couldn't register HandleStoreQuery: " + err.Error())
	}
	if err := serv.RegisterHandler(serv.HandleKeyQuery); err != nil {
		return errors.New("Couldn't register HandleKeyQuery: " + err.Error())
	}

	return nil
}

// Registers serv to the underlying onet.Context as a processor for all the possible types of messages
// received by another server. Upon reception of one of these messages, the method Process will be invoked.
func registerServerMsgHandler(c *onet.Context, serv *Service) {
	// Create Session
	c.RegisterProcessor(serv, messages.MsgTypes.MsgCreateSessionRequest)
	c.RegisterProcessor(serv, messages.MsgTypes.MsgCreateSessionReply)

	// Close Session
	c.RegisterProcessor(serv, messages.MsgTypes.MsgCloseSessionRequest)
	c.RegisterProcessor(serv, messages.MsgTypes.MsgCloseSessionReply)

	// Generate Public Key
	c.RegisterProcessor(serv, messages.MsgTypes.MsgGenPubKeyRequest)
	c.RegisterProcessor(serv, messages.MsgTypes.MsgGenPubKeyReply)

	// Generate Evaluation Key
	c.RegisterProcessor(serv, messages.MsgTypes.MsgGenEvalKeyRequest)
	c.RegisterProcessor(serv, messages.MsgTypes.MsgGenEvalKeyReply)

	// Generate Rotation Key
	c.RegisterProcessor(serv, messages.MsgTypes.MsgGenRotKeyRequest)
	c.RegisterProcessor(serv, messages.MsgTypes.MsgGenRotKeyReply)

	// Key
	c.RegisterProcessor(serv, messages.MsgTypes.MsgKeyRequest)
	c.RegisterProcessor(serv, messages.MsgTypes.MsgKeyReply)

	// Store
	c.RegisterProcessor(serv, messages.MsgTypes.MsgStoreRequest)
	c.RegisterProcessor(serv, messages.MsgTypes.MsgStoreReply)

	// Get Ciphertext
	c.RegisterProcessor(serv, messages.MsgTypes.MsgGetCipherRequest)
	c.RegisterProcessor(serv, messages.MsgTypes.MsgGetCipherReply)
}

// Retrieves Session from the underlying SessionStore. Returns boolean indicating success.
func (serv *Service) GetSession(id messages.SessionID) (s *Session, ok bool) {
	return serv.sessions.GetSession(id)
}

// Process processes messages from servers. It is called by the onet library upon reception of any of
// the messages registered in registerServerMsgHandler. For this reason, the Process method
// is bound to be a giant if-else-if, which "manually" dispatches based on the message type.
func (serv *Service) Process(msg *network.Envelope) {
	// Create Session
	if msg.MsgType.Equal(messages.MsgTypes.MsgCreateSessionRequest) {
		serv.processCreateSessionRequest(msg)
		return
	}
	if msg.MsgType.Equal(messages.MsgTypes.MsgCreateSessionReply) {
		serv.processCreateSessionReply(msg)
		return
	}

	// Close Session
	if msg.MsgType.Equal(messages.MsgTypes.MsgCloseSessionRequest) {
		serv.processCloseSessionRequest(msg)
		return
	}
	if msg.MsgType.Equal(messages.MsgTypes.MsgCloseSessionReply) {
		serv.processCloseSessionReply(msg)
		return
	}

	// Generate Public Key
	if msg.MsgType.Equal(messages.MsgTypes.MsgGenPubKeyRequest) {
		serv.processGenPubKeyRequest(msg)
		return
	}
	if msg.MsgType.Equal(messages.MsgTypes.MsgGenPubKeyReply) {
		serv.processGenPubKeyReply(msg)
		return
	}

	// Generate Evaluation Key
	if msg.MsgType.Equal(messages.MsgTypes.MsgGenEvalKeyRequest) {
		serv.processGenEvalKeyRequest(msg)
		return
	}
	if msg.MsgType.Equal(messages.MsgTypes.MsgGenEvalKeyReply) {
		serv.processGenEvalKeyReply(msg)
		return
	}

	// Generate Rotation Key
	if msg.MsgType.Equal(messages.MsgTypes.MsgGenRotKeyRequest) {
		serv.processGenRotKeyRequest(msg)
		return
	}
	if msg.MsgType.Equal(messages.MsgTypes.MsgGenRotKeyReply) {
		serv.processGenRotKeyReply(msg)
		return
	}

	// Key
	if msg.MsgType.Equal(messages.MsgTypes.MsgKeyRequest) {
		serv.processKeyRequest(msg)
		return
	}
	if msg.MsgType.Equal(messages.MsgTypes.MsgKeyReply) {
		serv.processKeyReply(msg)
		return
	}

	// Store
	if msg.MsgType.Equal(messages.MsgTypes.MsgStoreRequest) {
		serv.processStoreRequest(msg)
		return
	}
	if msg.MsgType.Equal(messages.MsgTypes.MsgStoreReply) {
		serv.processStoreReply(msg)
		return
	}

	// Get Cipher
	if msg.MsgType.Equal(messages.MsgTypes.MsgGetCipherRequest) {
		serv.processGetCipherRequest(msg)
		return
	}
	if msg.MsgType.Equal(messages.MsgTypes.MsgGetCipherReply) {
		serv.processGetCipherReply(msg)
		return
	}

	log.Error("Unknown message type:", msg.MsgType)
}
