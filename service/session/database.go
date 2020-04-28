package session

import (
	"github.com/ldsec/lattigo/bfv"
	"github.com/ldsec/lattigo/dbfv"
	"go.dedis.ch/onet/v3/log"
	"lattigo-smc/service/messages"
)

// Retrieves a ciphertext from the database, given its id. Returns a boolean indicating success.
func (s *Session) GetCiphertext(id messages.CipherID) (ct *bfv.Ciphertext, ok bool) {
	log.Lvl4(s.service.ServerIdentity(), "Retrieving ciphertext")

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
	ct, ok = s.service.RetrieveRemoteCiphertext(s.SessionID, id)
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