package session

import (
	"github.com/ldsec/lattigo/bfv"
	"go.dedis.ch/onet/v3/log"
)

func (s *Session) GetSecretKeyShare() *bfv.SecretKey {
	return s.skShard
}

// Returns the public key for this session. If not found locally, it tries at the root.
// Returns a boolean indicating success.
func (s *Session) GetPublicKey() (*bfv.PublicKey, bool) {
	log.Lvl4(s.service.ServerIdentity(), "Retrieving public key")

	// Try locally
	s.pubKeyLock.RLock()
	pk := s.publicKey
	s.pubKeyLock.RUnlock()

	// Get key owner
	s.pubKeyOwnerLock.RLock()
	owner := s.pubKeyOwner
	s.pubKeyOwnerLock.RUnlock()

	// If present, return (success).
	if pk != nil {
		return s.publicKey, true
	}

	// Else, if owner not set, return (failure)
	if owner == nil {
		log.Error(s.service.ServerIdentity(), "No owner set. Key not generated.")
		return nil, false
	}

	// Else, if we are the owner (we are supposed to have it) return (failure).
	if s.service.ServerIdentity().Equal(owner) {
		log.Error(s.service.ServerIdentity(), "We are owner. Key not generated.")
		return nil, false
	}

	// Else, try at the owner
	log.Lvl4(s.service.ServerIdentity(), "Retrieving remote public key")
	pk, ok := s.service.GetRemotePublicKey(s.SessionID, owner)
	// Cache the public key
	if ok {
		s.pubKeyLock.Lock()
		s.publicKey = pk
		s.pubKeyLock.Unlock()
	}

	return pk, ok
}

// Returns the evaluation key for this session. If not found locally, it tries at the root.
// Returns a boolean indicating success.
func (s *Session) GetEvaluationKey() (*bfv.EvaluationKey, bool) {
	log.Lvl4(s.service.ServerIdentity(), "Retrieving evaluation key")

	// Try locally
	s.evalKeyLock.RLock()
	evk := s.evalKey
	s.evalKeyLock.RUnlock()

	// Get key owner
	s.evalKeyOwnerLock.RLock()
	owner := s.evalKeyOwner
	s.evalKeyOwnerLock.RUnlock()

	// If present, return (success).
	if evk != nil {
		return s.evalKey, true
	}

	// Else, if owner not set, return (failure)
	if owner == nil {
		log.Error(s.service.ServerIdentity(), "No owner set. Key not generated.")
		return nil, false
	}

	// Else, if we are the owner (we are supposed to have it) return (failure).
	if s.service.ServerIdentity().Equal(owner) {
		log.Lvl3(s.service.ServerIdentity(), "We are owner. Key not generated.")
		return nil, false
	}

	// Else, try at the owner
	log.Lvl4(s.service.ServerIdentity(), "Retrieving remote evaluation key")
	evk, ok := s.service.GetRemoteEvalKey(s.SessionID, owner)
	// Cache the evaluation key
	if ok {
		s.evalKeyLock.Lock()
		s.evalKey = evk
		s.evalKeyLock.Unlock()
	}

	return evk, ok
}

// Returns the rotation key for this session. If not found locally, it tries at the root.
// Returns a boolean indicating success.
func (s *Session) GetRotationKey() (*bfv.RotationKeys, bool) {
	log.Lvl4(s.service.ServerIdentity(), "Retrieving rotation key")

	// Try locally
	s.rotKeyLock.RLock()
	rotk := s.rotationKey
	s.rotKeyLock.RUnlock()

	// Get key owner
	s.rotKeyOwnerLock.RLock()
	owner := s.rotKeyOwner
	s.rotKeyOwnerLock.RUnlock()

	// If present, return (success).
	if rotk != nil {
		return s.rotationKey, true
	}

	// Else, if owner not set, return (failure)
	if owner == nil {
		log.Error(s.service.ServerIdentity(), "No owner set. Key not generated.")
		return nil, false
	}

	// Else, if we are the owner (we are supposed to have it) return (failure).
	if s.service.ServerIdentity().Equal(owner) {
		log.Lvl3(s.service.ServerIdentity(), "We are owner. Key not generated.")
		return nil, false
	}

	// Else, try at the owner
	log.Lvl4(s.service.ServerIdentity(), "Retrieving remote rotation key")
	rotk, ok := s.service.GetRemoteRotationKey(s.SessionID, owner)
	// Cache the rotation key
	if ok {
		s.rotKeyLock.Lock()
		s.rotationKey = rotk
		s.rotKeyLock.Unlock()
	}

	return rotk, ok
}
