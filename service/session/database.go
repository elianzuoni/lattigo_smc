package session

import (
	"errors"
	"github.com/ldsec/lattigo/bfv"
	"github.com/ldsec/lattigo/dbfv"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
	"lattigo-smc/service/messages"
	"strconv"
	"strings"
)

// Retrieves a ciphertext from the database, given its id. Returns a boolean indicating success.
func (s *Session) GetCiphertext(id messages.CipherID) (ct *bfv.Ciphertext, ok bool) {
	log.Lvl4(s.service.ServerIdentity(), "Retrieving ciphertext")

	if id == messages.NilCipherID {
		log.Error(s.service.ServerIdentity(), "Queried on NilCipherID")
		return nil, false
	}

	owner := id.GetServerIdentityOwner()

	// Try locally
	s.ciphertextsLock.RLock()
	ct, ok = s.ciphertexts[id]
	s.ciphertextsLock.RUnlock()

	// If present, return (success)
	if ok {
		log.Lvl4(s.service.ServerIdentity(), "Found the ciphertext locally")
		return
	}

	// If not present, and we are the owner, return (failure).
	if owner.Equal(s.service.ServerIdentity()) {
		log.Error(s.service.ServerIdentity(), "We are owner of ciphertext, but it is not present")
		return
	}

	// Else, send a request to the owner
	log.Lvl4(s.service.ServerIdentity(), "Ciphertext is remote")
	ct, ok = s.service.GetRemoteCiphertext(s.SessionID, id)
	// Cache the ciphertext
	if ok {
		s.StoreCiphertext(id, ct)
	}

	return
}

// Writes a ciphertext in the database. Does not care about ownership (the ciphertext may be cached).
func (s *Session) StoreCiphertext(id messages.CipherID, ct *bfv.Ciphertext) {
	s.ciphertextsLock.Lock()
	s.ciphertexts[id] = ct
	s.ciphertextsLock.Unlock()

	return
}

// Stores a ciphertext in a database, under a new ID (we are the owner).
func (s *Session) StoreCiphertextNewID(ct *bfv.Ciphertext) messages.CipherID {
	newCipherID := messages.NewCipherID(s.service.ServerIdentity())
	s.StoreCiphertext(newCipherID, ct)
	return newCipherID
}

// Retrieves a CipherID, whether local or remote, given its full name
func (s *Session) GetCipherID(fullName string) (messages.CipherID, bool) {
	log.Lvl3(s.service.ServerIdentity(), "Retrieving CipherID")

	// Parse full name
	name, owner, err := s.parseVarFullName(fullName)
	if err != nil {
		log.Error(s.service.ServerIdentity(), "Could not parse full variable name:", err)
		return messages.NilCipherID, false
	}

	// If we are owner, retrieve it locally
	if owner.Equal(s.service.ServerIdentity()) {
		log.Lvl3(s.service.ServerIdentity(), "CipherID is local")
		return s.GetLocalCipherID(name)
	}

	// Else, send a request to the owner
	log.Lvl3(s.service.ServerIdentity(), "CipherID is remote")
	return s.service.GetRemoteCipherID(s.SessionID, name, owner)
}

// Retrieves a local CipherID, given its variable name
func (s *Session) GetLocalCipherID(name string) (messages.CipherID, bool) {
	s.cipherIDsLock.RLock()
	id, ok := s.cipherIDs[name]
	s.cipherIDsLock.RUnlock()

	return id, ok
}

// Parses the full name to get name and owner
func (s *Session) parseVarFullName(fullName string) (name string, owner *network.ServerIdentity, err error) {
	toks := strings.Split(fullName, "@")

	if len(toks) != 2 {
		err = errors.New("Mis-formed full variable name: length != 2 after splitting")
		return
	}

	name = toks[0]
	ownerIdx, err := strconv.Atoi(toks[1])
	if err != nil {
		return
	}
	if ownerIdx < 0 || ownerIdx >= len(s.Roster.List) {
		err = errors.New("Mis-formed full variable name: owner index out of bounds")
		return
	}

	owner = s.Roster.List[ownerIdx]
	return
}

// Stores a new CipherID under the given name
func (s *Session) StoreCipherID(name string, id messages.CipherID) {
	s.cipherIDsLock.Lock()
	s.cipherIDs[name] = id
	s.cipherIDsLock.Unlock()
}

// Retrieves an additive share from the database, given its id. Returns a boolean indicating success.
func (s *Session) GetAdditiveShare(id messages.SharesID) (share *dbfv.AdditiveShare, ok bool) {
	log.Lvl4("Retrieving additive share")
	s.sharesLock.RLock()
	share, ok = s.shares[id]
	s.sharesLock.RUnlock()

	return
}

// Writes an additive share in the database.
func (s *Session) StoreAdditiveShare(id messages.SharesID, share *dbfv.AdditiveShare) {
	s.sharesLock.Lock()
	s.shares[id] = share
	s.sharesLock.Unlock()

	return
}

// This method returns a finaliser (as required by the EncryptionToSharesProtocol constructor)
// that saves the share under the provided CipherID in the Service's shares database.
func (s *Session) NewShareFinaliser(sharesID messages.SharesID) func(share *dbfv.AdditiveShare) {
	return func(share *dbfv.AdditiveShare) {
		s.StoreAdditiveShare(sharesID, share)
	}
}
