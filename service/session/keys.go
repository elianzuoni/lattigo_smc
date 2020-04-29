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

	// If present, return (success).
	if pk != nil {
		return s.publicKey, true
	}

	// Else, if we are the root (we are supposed to have it) return (failure).
	if s.service.ServerIdentity().Equal(s.Root) {
		log.Lvl3(s.service.ServerIdentity(), "We are root. Key not generated.")
		return nil, false
	}

	// Else, try at the root
	log.Lvl4(s.service.ServerIdentity(), "Retrieving remote public key")
	pk, ok := s.service.GetRemotePublicKey(s.SessionID)
	// Cache the public key
	if ok {
		s.publicKey = pk
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

	// If present, return (success).
	if evk != nil {
		return s.evalKey, true
	}

	// Else, if we are the root (we are supposed to have it) return (failure).
	if s.service.ServerIdentity().Equal(s.Root) {
		log.Lvl3(s.service.ServerIdentity(), "We are root. Key not generated.")
		return nil, false
	}

	// Else, try at the root
	log.Lvl4(s.service.ServerIdentity(), "Retrieving remote evaluation key")
	evk, ok := s.service.GetRemoteEvalKey(s.SessionID)
	// Cache the evaluation key
	if ok {
		s.evalKey = evk
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

	// If present, return (success).
	if rotk != nil {
		return s.rotationKey, true
	}

	// Else, if we are the root (we are supposed to have it) return (failure).
	if s.service.ServerIdentity().Equal(s.Root) {
		log.Lvl3(s.service.ServerIdentity(), "We are root. Key not generated.")
		return nil, false
	}

	// Else, try at the root
	log.Lvl4(s.service.ServerIdentity(), "Retrieving remote rotation key")
	rotk, ok := s.service.GetRemoteRotationKey(s.SessionID)
	// Cache the rotation key
	if ok {
		s.rotationKey = rotk
	}

	return rotk, ok
}
