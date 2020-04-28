package session

import (
	"github.com/ldsec/lattigo/bfv"
	"github.com/ldsec/lattigo/dbfv"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"lattigo-smc/service/messages"
	"sync"
)

type Session struct {
	SessionID messages.SessionID

	service *Service
	Roster  *onet.Roster

	// These variables are set upon construction.
	Params  *bfv.Parameters
	SkShard *bfv.SecretKey
	// These variables have to be set via an explicit Query.
	PubKeyLock      sync.RWMutex
	MasterPublicKey *bfv.PublicKey
	RotKeyLock      sync.RWMutex
	RotationKey     *bfv.RotationKeys
	EvalKeyLock     sync.RWMutex
	EvalKey         *bfv.EvaluationKey

	// Stores ciphertexts.
	ciphertextsLock sync.RWMutex
	ciphertexts     map[messages.CipherID]*bfv.Ciphertext
	// Stores additive shares.
	sharesLock sync.RWMutex
	shares     map[messages.SharesID]*dbfv.AdditiveShare

	// Synchronisation point between HandleQuery and the corresponding processReply
	GenPubKeyRepLock   sync.RWMutex
	GenPubKeyReplies   map[messages.GenPubKeyRequestID]chan *messages.GenPubKeyReply
	GenEvalKeyRepLock  sync.RWMutex
	GenEvalKeyReplies  map[messages.GenEvalKeyRequestID]chan *messages.GenEvalKeyReply
	GenRotKeyRepLock   sync.RWMutex
	GenRotKeyReplies   map[messages.GenRotKeyRequestID]chan *messages.GenRotKeyReply
	KeyRepLock         sync.RWMutex
	KeyReplies         map[messages.KeyRequestID]chan *messages.KeyReply
	StoreRepLock       sync.RWMutex
	StoreReplies       map[messages.StoreRequestID]chan *messages.StoreReply
	SumRepLock         sync.RWMutex
	SumReplies         map[messages.SumRequestID]chan *messages.SumReply
	MultiplyRepLock    sync.RWMutex
	MultiplyReplies    map[messages.MultiplyRequestID]chan *messages.MultiplyReply
	RelinRepLock       sync.RWMutex
	RelinReplies       map[messages.RelinRequestID]chan *messages.RelinReply
	RotationRepLock    sync.RWMutex
	RotationReplies    map[messages.RotationRequestID]chan *messages.RotationReply
	RetrieveRepLock    sync.RWMutex
	RetrieveReplies    map[messages.RetrieveRequestID]chan *messages.RetrieveReply
	RefreshRepLock     sync.RWMutex
	RefreshReplies     map[messages.RefreshRequestID]chan *messages.RefreshReply
	EncToSharesRepLock sync.RWMutex
	EncToSharesReplies map[messages.EncToSharesRequestID]chan *messages.EncToSharesReply
	SharesToEncRepLock sync.RWMutex
	SharesToEncReplies map[messages.SharesToEncRequestID]chan *messages.SharesToEncReply
}

type SessionStore struct {
	// Useful to launch requests from the Session object
	service *Service

	sessionsLock sync.RWMutex
	sessions     map[messages.SessionID]*Session
}

// Constructor of SessionStore
func NewSessionStore(serv *Service) *SessionStore {
	log.Lvl2("Creating new SessionStore")

	return &SessionStore{
		service: serv,

		sessionsLock: sync.RWMutex{},
		sessions:     make(map[messages.SessionID]*Session),
	}
}

// Constructor of Session. Already requires roster and bfv parameters.
func (store *SessionStore) NewSession(id messages.SessionID, roster *onet.Roster, params *bfv.Parameters) {
	log.Lvl2("Session constructor started")

	session := &Session{
		SessionID: id,

		service: store.service,
		Roster:  roster,

		Params: params,

		// No need to initialise pubKeyLock, rotKeyLock, and evalKeyLock

		// No need to initialise ciphertextsLock
		ciphertexts: make(map[messages.CipherID]*bfv.Ciphertext),
		// No need to initialise sharesLock
		shares: make(map[messages.SharesID]*dbfv.AdditiveShare),

		// No need to initialise locks
		GenPubKeyReplies:   make(map[messages.GenPubKeyRequestID]chan *messages.GenPubKeyReply),
		GenEvalKeyReplies:  make(map[messages.GenEvalKeyRequestID]chan *messages.GenEvalKeyReply),
		GenRotKeyReplies:   make(map[messages.GenRotKeyRequestID]chan *messages.GenRotKeyReply),
		KeyReplies:         make(map[messages.KeyRequestID]chan *messages.KeyReply),
		StoreReplies:       make(map[messages.StoreRequestID]chan *messages.StoreReply),
		SumReplies:         make(map[messages.SumRequestID]chan *messages.SumReply),
		MultiplyReplies:    make(map[messages.MultiplyRequestID]chan *messages.MultiplyReply),
		RelinReplies:       make(map[messages.RelinRequestID]chan *messages.RelinReply),
		RotationReplies:    make(map[messages.RotationRequestID]chan *messages.RotationReply),
		RetrieveReplies:    make(map[messages.RetrieveRequestID]chan *messages.RetrieveReply),
		RefreshReplies:     make(map[messages.RefreshRequestID]chan *messages.RefreshReply),
		EncToSharesReplies: make(map[messages.EncToSharesRequestID]chan *messages.EncToSharesReply),
		SharesToEncReplies: make(map[messages.SharesToEncRequestID]chan *messages.SharesToEncReply),
	}

	keygen := bfv.NewKeyGenerator(params)
	session.SkShard = keygen.GenSecretKey()

	// Store new session
	store.sessionsLock.Lock()
	store.sessions[id] = session
	store.sessionsLock.Unlock()

	return
}

// Method to retrieve Session. Returns boolean indicating success
func (store *SessionStore) GetSession(id messages.SessionID) (s *Session, ok bool) {
	store.sessionsLock.RLock()
	s, ok = store.sessions[id]
	store.sessionsLock.RUnlock()

	return
}

// Method to delete Session from SessionStore. Does nothing if session does not exist.
func (store *SessionStore) DeleteSession(id messages.SessionID) {
	log.Lvl2("Deleting session")

	store.sessionsLock.Lock()
	delete(store.sessions, id)
	store.sessionsLock.Unlock()

	return
}
