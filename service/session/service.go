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
	/*
		createSessionRepLock sync.RWMutex
		createSessionReplies map[messages.CreateSessionRequestID]chan *messages.CreateSessionReply

	*/
	closeSessionRepLock sync.RWMutex
	closeSessionReplies map[messages.CloseSessionRequestID]chan *messages.CloseSessionReply
	genPubKeyRepLock    sync.RWMutex
	genPubKeyReplies    map[messages.GenPubKeyRequestID]chan *messages.GenPubKeyReply
	genEvalKeyRepLock   sync.RWMutex
	genEvalKeyReplies   map[messages.GenEvalKeyRequestID]chan *messages.GenEvalKeyReply
	genRotKeyRepLock    sync.RWMutex
	genRotKeyReplies    map[messages.GenRotKeyRequestID]chan *messages.GenRotKeyReply
	getPubKeyRepLock    sync.RWMutex
	getPubKeyReplies    map[messages.GetPubKeyRequestID]chan *messages.GetPubKeyReply
	getEvalKeyRepLock   sync.RWMutex
	getEvalKeyReplies   map[messages.GetEvalKeyRequestID]chan *messages.GetEvalKeyReply
	getRotKeyRepLock    sync.RWMutex
	getRotKeyReplies    map[messages.GetRotKeyRequestID]chan *messages.GetRotKeyReply
	/*
		keyRepLock           sync.RWMutex
		keyReplies           map[messages.KeyRequestID]chan *messages.KeyReply

	*/
	storeRepLock     sync.RWMutex
	storeReplies     map[messages.StoreRequestID]chan *messages.StoreReply
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

		/*
			createSessionReplies: make(map[messages.CreateSessionRequestID]chan *messages.CreateSessionReply),

		*/
		closeSessionReplies: make(map[messages.CloseSessionRequestID]chan *messages.CloseSessionReply),
		genPubKeyReplies:    make(map[messages.GenPubKeyRequestID]chan *messages.GenPubKeyReply),
		genEvalKeyReplies:   make(map[messages.GenEvalKeyRequestID]chan *messages.GenEvalKeyReply),
		genRotKeyReplies:    make(map[messages.GenRotKeyRequestID]chan *messages.GenRotKeyReply),
		/*
			keyReplies:           make(map[messages.KeyRequestID]chan *messages.KeyReply),

		*/
		storeReplies:     make(map[messages.StoreRequestID]chan *messages.StoreReply),
		getCipherReplies: make(map[messages.GetCipherRequestID]chan *messages.GetCipherReply),
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
	/*
		if err := serv.RegisterHandler(serv.HandleKeyQuery); err != nil {
			return errors.New("Couldn't register HandleKeyQuery: " + err.Error())
		}

	*/

	return nil
}

// Registers serv to the underlying onet.Context as a processor for all the possible types of messages
// received by another server. Upon reception of one of these messages, the method Process will be invoked.
func registerServerMsgHandler(c *onet.Context, serv *Service) {
	/*
		// Create Session
		c.RegisterProcessor(serv, messages.MsgTypes.MsgCreateSessionRequest)
		c.RegisterProcessor(serv, messages.MsgTypes.MsgCreateSessionReply)

	*/

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

	/*
		// Key
		c.RegisterProcessor(serv, messages.MsgTypes.MsgKeyRequest)
		c.RegisterProcessor(serv, messages.MsgTypes.MsgKeyReply)

	*/

	// Get Public Key
	c.RegisterProcessor(serv, messages.MsgTypes.MsgGetPubKeyRequest)
	c.RegisterProcessor(serv, messages.MsgTypes.MsgGetPubKeyReply)

	// Get Evaluation Key
	c.RegisterProcessor(serv, messages.MsgTypes.MsgGetEvalKeyRequest)
	c.RegisterProcessor(serv, messages.MsgTypes.MsgGetEvalKeyReply)

	// Get Rotation Key
	c.RegisterProcessor(serv, messages.MsgTypes.MsgGetRotKeyRequest)
	c.RegisterProcessor(serv, messages.MsgTypes.MsgGetRotKeyReply)

	// Store
	c.RegisterProcessor(serv, messages.MsgTypes.MsgStoreRequest)
	c.RegisterProcessor(serv, messages.MsgTypes.MsgStoreReply)

	// Get Ciphertext
	c.RegisterProcessor(serv, messages.MsgTypes.MsgGetCipherRequest)
	c.RegisterProcessor(serv, messages.MsgTypes.MsgGetCipherReply)
}

// Retrieves Session from the underlying SessionStore. Returns boolean indicating success.
func (service *Service) GetSession(id messages.SessionID) (s *Session, ok bool) {
	return service.sessions.GetSession(id)
}

// Process processes messages from servers. It is called by the onet library upon reception of any of
// the messages registered in registerServerMsgHandler. For this reason, the Process method
// is bound to be a giant if-else-if, which "manually" dispatches based on the message type.
func (service *Service) Process(msg *network.Envelope) {
	/*
		// Create Session
		if msg.MsgType.Equal(messages.MsgTypes.MsgCreateSessionRequest) {
			service.processCreateSessionRequest(msg)
			return
		}
		if msg.MsgType.Equal(messages.MsgTypes.MsgCreateSessionReply) {
			service.processCreateSessionReply(msg)
			return
		}

	*/

	// Close Session
	if msg.MsgType.Equal(messages.MsgTypes.MsgCloseSessionRequest) {
		service.processCloseSessionRequest(msg)
		return
	}
	if msg.MsgType.Equal(messages.MsgTypes.MsgCloseSessionReply) {
		service.processCloseSessionReply(msg)
		return
	}

	// Generate Public Key
	if msg.MsgType.Equal(messages.MsgTypes.MsgGenPubKeyRequest) {
		service.processGenPubKeyRequest(msg)
		return
	}
	if msg.MsgType.Equal(messages.MsgTypes.MsgGenPubKeyReply) {
		service.processGenPubKeyReply(msg)
		return
	}

	// Generate Evaluation Key
	if msg.MsgType.Equal(messages.MsgTypes.MsgGenEvalKeyRequest) {
		service.processGenEvalKeyRequest(msg)
		return
	}
	if msg.MsgType.Equal(messages.MsgTypes.MsgGenEvalKeyReply) {
		service.processGenEvalKeyReply(msg)
		return
	}

	// Generate Rotation Key
	if msg.MsgType.Equal(messages.MsgTypes.MsgGenRotKeyRequest) {
		service.processGenRotKeyRequest(msg)
		return
	}
	if msg.MsgType.Equal(messages.MsgTypes.MsgGenRotKeyReply) {
		service.processGenRotKeyReply(msg)
		return
	}

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

	/*
		// Key
		if msg.MsgType.Equal(messages.MsgTypes.MsgKeyRequest) {
			service.processKeyRequest(msg)
			return
		}
		if msg.MsgType.Equal(messages.MsgTypes.MsgKeyReply) {
			service.processKeyReply(msg)
			return
		}

	*/

	// Store
	if msg.MsgType.Equal(messages.MsgTypes.MsgStoreRequest) {
		service.processStoreRequest(msg)
		return
	}
	if msg.MsgType.Equal(messages.MsgTypes.MsgStoreReply) {
		service.processStoreReply(msg)
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

	log.Error("Unknown message type:", msg.MsgType)
}
