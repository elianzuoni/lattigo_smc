package session

import (
	"github.com/ldsec/lattigo/bfv"
	"github.com/ldsec/lattigo/dbfv"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
	"lattigo-smc/service/messages"
	"sync"
)

type Session struct {
	SessionID messages.SessionID

	service *Service
	Roster  *onet.Roster

	Params           *bfv.Parameters
	skShard          *bfv.SecretKey
	pubKeyLock       sync.RWMutex
	publicKey        *bfv.PublicKey
	pubKeyOwnerLock  sync.RWMutex
	pubKeyOwner      *network.ServerIdentity
	rotKeyLock       sync.RWMutex
	rotationKey      *bfv.RotationKeys
	rotKeyOwnerLock  sync.RWMutex
	rotKeyOwner      *network.ServerIdentity
	evalKeyLock      sync.RWMutex
	evalKey          *bfv.EvaluationKey
	evalKeyOwnerLock sync.RWMutex
	evalKeyOwner     *network.ServerIdentity

	// Stores ciphertexts.
	ciphertextsLock sync.RWMutex
	ciphertexts     map[messages.CipherID]*bfv.Ciphertext
	// Stores additive shares.
	sharesLock sync.RWMutex
	shares     map[messages.SharesID]*dbfv.AdditiveShare
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
	}

	keygen := bfv.NewKeyGenerator(params)
	session.skShard = keygen.GenSecretKey()

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
