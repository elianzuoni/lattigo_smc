package circuit

import (
	"errors"
	"github.com/ldsec/lattigo/bfv"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
	"lattigo-smc/service/messages"
)

// Legacy query
func (service *Service) HandleRotationQuery(query *messages.RotationQuery) (network.Message, error) {
	log.Lvl1(service.ServerIdentity(), "Received RotationQuery for ciphertext:", query.CipherID)

	/*
		// Extract Session, if existent
		s, ok := service.GetSessionService().GetSession(query.SessionID)
		if !ok {
			err := errors.New("Requested session does not exist")
			log.Error(service.ServerIdentity(), err)
			return nil, err
		}

		// Create request with its ID
		reqID := messages.NewRotationRequestID()
		req := &messages.RotationRequest{query.SessionID, reqID, query}

		// Create channel before sending request to root.
		service.rotationRepLock.Lock()
		service.rotationReplies[reqID] = make(chan *messages.RotationReply)
		service.rotationRepLock.Unlock()

		// Send request to root
		log.Lvl2(service.ServerIdentity(), "Sending RotationRequest to root:", query.CipherID)
		tree := s.Roster.GenerateBinaryTree()
		err := service.SendRaw(tree.Root.ServerIdentity, req)
		if err != nil {
			log.Error("Couldn't send RotationRequest to root:", err)
			return nil, err
		}

		// Receive reply from channel
		log.Lvl3(service.ServerIdentity(), "Forwarded request to the root. Waiting to receive reply...")
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

		// Check validity
		if !reply.Valid {
			err := errors.New("Received invalid reply: root couldn't perform sum")
			log.Error(service.ServerIdentity(), err)
			// Respond with the reply, not nil, err
		} else {
			log.Lvl4(service.ServerIdentity(), "Received valid reply from channel")
		}

		return &messages.RotationResponse{reply.NewCipherID, reply.Valid}, nil

	*/

	rotID, err := service.rotateCipher(query.SessionID, query.CipherID, query.RotIdx, query.K)
	return &messages.RotationResponse{rotID, err == nil}, err
}

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
	rotKey, ok := s.GetRotationKey()
	if !ok {
		err := errors.New("Could not retrieve rotation key")
		log.Error(service.ServerIdentity(), err)
		return messages.NilCipherID, err
	}
	// TODO: refine check for specific rotation

	// Rotate
	log.Lvl3(service.ServerIdentity(), "Rotating the ciphertexts")
	eval := bfv.NewEvaluator(s.Params)
	var ctRot *bfv.Ciphertext
	switch bfv.Rotation(rotIdx) {
	case bfv.RotationRow:
		ctRot = eval.RotateRowsNew(ct, rotKey)
	// TODO: what? they are the same?
	case bfv.RotationLeft:
		ctRot = eval.RotateColumnsNew(ct, k, rotKey)
	case bfv.RotationRight:
		ctRot = eval.RotateColumnsNew(ct, k, rotKey)
	}

	// Store locally
	rotID := s.StoreCiphertextNewID(ctRot)

	return rotID, nil
}

// To be modified

// This method is executed at the root when receiving a RotationRequest.
// It checks for feasibility (whether or not it possesses the requested ciphertext) and, based on the result,
// it either returns an invalid reply, or performs the rotation and stores the new ciphertext under a new
// CipherID which is returned in a valid reply.
// TODO: it only check whether rotKeys is nil. If not, but the right rotation key was not generated, it panics.
func (service *Service) processRotationRequest(msg *network.Envelope) {
	req := (msg.Msg).(*messages.RotationRequest)

	log.Lvl1(service.ServerIdentity(), "Root. Received RotationRequest for ciphertext", req.Query.CipherID)

	// Start by declaring reply with minimal fields.
	reply := &messages.RotationReply{SessionID: req.SessionID, ReqID: req.ReqID, NewCipherID: messages.NilCipherID, Valid: false}

	// Extract Session, if existent
	s, ok := service.GetSessionService().GetSession(req.SessionID)
	if !ok {
		log.Error(service.ServerIdentity(), "Requested session does not exist")
		// Send negative response
		err := service.SendRaw(msg.ServerIdentity, reply)
		if err != nil {
			log.Error("Could not send reply : ", err)
		}
		return
	}

	// Check feasibility
	log.Lvl3(service.ServerIdentity(), "Checking existence of ciphertext")
	ct, ok := s.GetCiphertext(req.Query.CipherID)
	if !ok {
		log.Error(service.ServerIdentity(), "Ciphertext", req.Query.CipherID, "does not exist.")
		err := service.SendRaw(msg.ServerIdentity, reply)
		if err != nil {
			log.Error(service.ServerIdentity(), "Could not reply (negatively) to server:", err)
		}
		return
	}
	log.Lvl3(service.ServerIdentity(), "Checking if rotation key was generated")
	// The rotation key is modifiable, but it is the pointer s.rotationKey itself that changes, not its content
	rotKey, ok := s.GetRotationKey()
	if !ok {
		log.Error(service.ServerIdentity(), "Rotation key not generated")
		err := service.SendRaw(msg.ServerIdentity, reply)
		if err != nil {
			log.Error(service.ServerIdentity(), "Could not reply (negatively) to server:", err)
		}
		return
	}
	// TODO: refine check for specific rotation

	// Evaluate the rotation
	log.Lvl3(service.ServerIdentity(), "Evaluating the rotation of the ciphertexts")
	eval := bfv.NewEvaluator(s.Params)
	var ctRot *bfv.Ciphertext
	switch bfv.Rotation(req.Query.RotIdx) {
	case bfv.RotationRow:
		ctRot = eval.RotateRowsNew(ct, rotKey)
	// TODO: what? they are the same?
	case bfv.RotationLeft:
		ctRot = eval.RotateColumnsNew(ct, req.Query.K, rotKey)
	case bfv.RotationRight:
		ctRot = eval.RotateColumnsNew(ct, req.Query.K, rotKey)
	}

	// Register in local database
	idRot := messages.NewCipherID(service.ServerIdentity())
	s.StoreCiphertext(idRot, ctRot)

	// Set fields in reply
	reply.NewCipherID = idRot
	reply.Valid = true

	// Send reply to server
	log.Lvl2(service.ServerIdentity(), "Sending positive reply to server")
	err := service.SendRaw(msg.ServerIdentity, reply)
	if err != nil {
		log.Error("Could not reply (positively) to server:", err)
	}
	log.Lvl4(service.ServerIdentity(), "Sent positive reply to server")

	return
}

// This method is executed at the server when receiving the root's RotationReply.
// It simply sends the reply through the channel.
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
