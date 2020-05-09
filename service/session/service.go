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

	// Synchronisation points on which a reply from a contacted server is waited for
	getPubKeyRepLock   sync.RWMutex
	getPubKeyReplies   map[messages.GetPubKeyRequestID]chan *messages.GetPubKeyReply
	getEvalKeyRepLock  sync.RWMutex
	getEvalKeyReplies  map[messages.GetEvalKeyRequestID]chan *messages.GetEvalKeyReply
	getRotKeyRepLock   sync.RWMutex
	getRotKeyReplies   map[messages.GetRotKeyRequestID]chan *messages.GetRotKeyReply
	getCipherRepLock   sync.RWMutex
	getCipherReplies   map[messages.GetCipherRequestID]chan *messages.GetCipherReply
	getCipherIDRepLock sync.RWMutex
	getCipherIDReplies map[messages.GetCipherIDRequestID]chan *messages.GetCipherIDReply
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

		getPubKeyReplies:   make(map[messages.GetPubKeyRequestID]chan *messages.GetPubKeyReply),
		getEvalKeyReplies:  make(map[messages.GetEvalKeyRequestID]chan *messages.GetEvalKeyReply),
		getRotKeyReplies:   make(map[messages.GetRotKeyRequestID]chan *messages.GetRotKeyReply),
		getCipherReplies:   make(map[messages.GetCipherRequestID]chan *messages.GetCipherReply),
		getCipherIDReplies: make(map[messages.GetCipherIDRequestID]chan *messages.GetCipherIDReply),
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

	return nil
}

// Registers serv to the underlying onet.Context as a processor for all the possible types of messages
// received by another server. Upon reception of one of these messages, the method Process will be invoked.
func registerServerMsgHandler(c *onet.Context, serv *Service) {
	// Get Public Key
	c.RegisterProcessor(serv, messages.MsgTypes.MsgGetPubKeyRequest)
	c.RegisterProcessor(serv, messages.MsgTypes.MsgGetPubKeyReply)

	// Get Evaluation Key
	c.RegisterProcessor(serv, messages.MsgTypes.MsgGetEvalKeyRequest)
	c.RegisterProcessor(serv, messages.MsgTypes.MsgGetEvalKeyReply)

	// Get Rotation Key
	c.RegisterProcessor(serv, messages.MsgTypes.MsgGetRotKeyRequest)
	c.RegisterProcessor(serv, messages.MsgTypes.MsgGetRotKeyReply)

	// Get Ciphertext
	c.RegisterProcessor(serv, messages.MsgTypes.MsgGetCipherRequest)
	c.RegisterProcessor(serv, messages.MsgTypes.MsgGetCipherReply)

	// Get CipherID
	c.RegisterProcessor(serv, messages.MsgTypes.MsgGetCipherIDRequest)
	c.RegisterProcessor(serv, messages.MsgTypes.MsgGetCipherIDReply)
}

// Retrieves Session from the underlying SessionStore. Returns boolean indicating success.
func (service *Service) GetSession(id messages.SessionID) (s *Session, ok bool) {
	return service.sessions.GetSession(id)
}

// Process processes messages from servers. It is called by the onet library upon reception of any of
// the messages registered in registerServerMsgHandler. For this reason, the Process method
// is bound to be a giant if-else-if, which "manually" dispatches based on the message type.
func (service *Service) Process(msg *network.Envelope) {
	// Get Public Key
	if msg.MsgType.Equal(messages.MsgTypes.MsgGetPubKeyRequest) {
		service.processGetPubKeyRequest(msg)
		return
	}
	if msg.MsgType.Equal(messages.MsgTypes.MsgGetPubKeyReply) {
		service.processGetPubKeyReply(msg)
		return
	}

	// Get Evaluation Key
	if msg.MsgType.Equal(messages.MsgTypes.MsgGetEvalKeyRequest) {
		service.processGetEvalKeyRequest(msg)
		return
	}
	if msg.MsgType.Equal(messages.MsgTypes.MsgGetEvalKeyReply) {
		service.processGetEvalKeyReply(msg)
		return
	}

	// Get Rotation Key
	if msg.MsgType.Equal(messages.MsgTypes.MsgGetRotKeyRequest) {
		service.processGetRotKeyRequest(msg)
		return
	}
	if msg.MsgType.Equal(messages.MsgTypes.MsgGetRotKeyReply) {
		service.processGetRotKeyReply(msg)
		return
	}

	// Get Cipher
	if msg.MsgType.Equal(messages.MsgTypes.MsgGetCipherRequest) {
		service.processGetCipherRequest(msg)
		return
	}
	if msg.MsgType.Equal(messages.MsgTypes.MsgGetCipherReply) {
		service.processGetCipherReply(msg)
		return
	}

	// Get CipherID
	if msg.MsgType.Equal(messages.MsgTypes.MsgGetCipherIDRequest) {
		service.processGetCipherIDRequest(msg)
		return
	}
	if msg.MsgType.Equal(messages.MsgTypes.MsgGetCipherIDReply) {
		service.processGetCipherIDReply(msg)
		return
	}

	log.Error("Unknown message type:", msg.MsgType)
}
