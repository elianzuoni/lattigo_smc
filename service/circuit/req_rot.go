package circuit

import (
	"errors"
	"github.com/ldsec/lattigo/bfv"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
	"lattigo-smc/service/messages"
)

// Delegates the rotation of the ciphertext indexed by its ID to its owner.
func (service *Service) DelegateRotateCipher(sessionID messages.SessionID, cipherID messages.CipherID, rotIdx int,
	k uint64) (messages.CipherID, error) {
	log.Lvl1(service.ServerIdentity(), "Delegating rotation:", cipherID)

	// Check that the input is not NilCipherID: otherwise, return NilCipherID
	if cipherID == messages.NilCipherID {
		err := errors.New("The inputs is NilCipherID")
		log.Error(service.ServerIdentity(), err)
		return messages.NilCipherID, err
	}

	// Create RotationRequest with its ID
	reqID := messages.NewRotationRequestID()
	req := &messages.RotationRequest{reqID, sessionID, cipherID, k, rotIdx}

	// Create channel before sending request to root.
	service.rotationRepLock.Lock()
	service.rotationReplies[reqID] = make(chan *messages.RotationReply)
	service.rotationRepLock.Unlock()

	// Send request to owner of the ciphertext
	log.Lvl2(service.ServerIdentity(), "Sending RotationRequest to owner of ciphertext:", reqID)
	err := service.SendRaw(cipherID.GetServerIdentityOwner(), req)
	if err != nil {
		err = errors.New("Couldn't send RotationRequest to owner: " + err.Error())
		log.Error(err)
		return messages.NilCipherID, err
	}

	// Receive reply from channel
	log.Lvl3(service.ServerIdentity(), "Forwarded request to the owner. Waiting to receive reply...")
	service.rotationRepLock.RLock()
	replyChan := service.rotationReplies[reqID]
	service.rotationRepLock.RUnlock()
	reply := <-replyChan // TODO: timeout if root cannot send reply

	// Close channel
	log.Lvl3(service.ServerIdentity(), "Received reply from channel. Closing it.")
	service.rotationRepLock.Lock()
	close(replyChan)
	delete(service.rotationReplies, reqID)
	service.rotationRepLock.Unlock()

	log.Lvl4(service.ServerIdentity(), "Closed channel")

	if !reply.Valid {
		err := errors.New("Received invalid reply: owner couldn't perform rotation")
		log.Error(service.ServerIdentity(), err)

		return messages.NilCipherID, err
	}

	log.Lvl4(service.ServerIdentity(), "Received valid reply from channel:", reply.NewCipherID)

	return reply.NewCipherID, nil
}

// The RotationRequest is received by the owner of the ciphertext.
func (service *Service) processRotationRequest(msg *network.Envelope) {
	req := (msg.Msg).(*messages.RotationRequest)

	log.Lvl1(service.ServerIdentity(), "Received RotationRequest for ciphertext", req.CipherID)

	// Start by declaring reply with minimal fields.
	reply := &messages.RotationReply{SessionID: req.SessionID, ReqID: req.ReqID, Valid: false}

	// Rotate the ciphertext
	newCipherID, err := service.rotateCipher(req.SessionID, req.CipherID, req.RotIdx, req.K)
	if err != nil {
		log.Error(service.ServerIdentity(), "Could not rotate the ciphertext:", err)
	}

	// Set fields in reply
	reply.Valid = (err == nil)
	reply.NewCipherID = newCipherID

	// Send reply to server
	log.Lvl2(service.ServerIdentity(), "Sending positive reply to server")
	err = service.SendRaw(msg.ServerIdentity, reply)
	if err != nil {
		log.Error("Could not reply (positively) to server:", err)
	}
	log.Lvl4(service.ServerIdentity(), "Sent positive reply to server")

	return
}

// Rotates the ciphertext indexed by its ID.
func (service *Service) rotateCipher(sessionID messages.SessionID, cipherID messages.CipherID,
	rotIdx int, k uint64) (messages.CipherID, error) {
	log.Lvl2(service.ServerIdentity(), "Rotating ciphertext")

	// Extract Session, if existent
	s, ok := service.GetSessionService().GetSession(sessionID)
	if !ok {
		err := errors.New("Requested session does not exist")
		log.Error(service.ServerIdentity(), err)
		return messages.NilCipherID, err
	}

	// Retrieve ciphertext
	log.Lvl3(service.ServerIdentity(), "Retrieving ciphertext")
	ct, ok := s.GetCiphertext(cipherID)
	if !ok {
		err := errors.New("Ciphertext does not exist.")
		log.Error(service.ServerIdentity(), err)
		return messages.NilCipherID, err
	}
	// Retrieving rotation key
	log.Lvl3(service.ServerIdentity(), "Checking if rotation key was generated")
	// The rotation key is modifiable, but it is the pointer s.rotationKey itself that changes, not its content
	rotKey, ok := s.GetRotationKey(rotIdx, k)
	if !ok {
		err := errors.New("Could not retrieve rotation key")
		log.Error(service.ServerIdentity(), err)
		return messages.NilCipherID, err
	}

	// Rotate

	log.Lvl3(service.ServerIdentity(), "Rotating the ciphertext")

	// Reduce K modulo n/2 (each row is long n/2)
	k &= (1 << (s.Params.LogN - 1)) - 1

	// Only left-rotation is available. If right-rotation is requested, transform it into a left-rotation.
	if rotIdx == bfv.RotationRight {
		rotIdx = bfv.RotationLeft
		k = (1 << (s.Params.LogN - 1)) - k
	}

	eval := bfv.NewEvaluator(s.Params)
	var ctRot *bfv.Ciphertext
	switch bfv.Rotation(rotIdx) {
	case bfv.RotationRow:
		ctRot = eval.RotateRowsNew(ct, rotKey)
	case bfv.RotationLeft:
		ctRot = eval.RotateColumnsNew(ct, k, rotKey)
	}

	// Store locally
	rotID := s.StoreCiphertextNewID(ctRot)

	return rotID, nil
}

// The RotationReply is received by the server which sent the request. This method only sends the reply through the
// channel on which DelegateRotateCipher is waiting.
func (service *Service) processRotationReply(msg *network.Envelope) {
	reply := (msg.Msg).(*messages.RotationReply)

	log.Lvl1(service.ServerIdentity(), "Received RotationReply:", reply.ReqID)

	// Simply send reply through channel
	service.rotationRepLock.RLock()
	service.rotationReplies[reply.ReqID] <- reply
	service.rotationRepLock.RUnlock()
	log.Lvl4(service.ServerIdentity(), "Sent reply through channel")

	return
}

// Legacy query
func (service *Service) HandleRotationQuery(query *messages.RotationQuery) (network.Message, error) {
	log.Lvl1(service.ServerIdentity(), "Received RotationQuery for ciphertext:", query.CipherID)

	rotID, err := service.rotateCipher(query.SessionID, query.CipherID, query.RotIdx, query.K)
	return &messages.RotationResponse{rotID, err == nil}, err
}
