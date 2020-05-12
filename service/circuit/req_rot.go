package circuit

import (
	"errors"
	"github.com/ldsec/lattigo/bfv"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
	"lattigo-smc/service/messages"
	"time"
)

// Delegates the rotation of the ciphertext indexed by its ID to its owner.
func (service *Service) DelegateRotateCipher(sessionID messages.SessionID, cipherID messages.CipherID, rotIdx int,
	k uint64) (messages.CipherID, error) {
	log.Lvl1(service.ServerIdentity(), "(rotIdx =", rotIdx, ", k =", k, ")\n", "Delegating rotation:", cipherID)

	// Check that the input is not NilCipherID: otherwise, return NilCipherID
	if cipherID == messages.NilCipherID {
		err := errors.New("The input is NilCipherID")
		log.Error(service.ServerIdentity(), "(rotIdx =", rotIdx, ", k =", k, ")\n", err)
		return messages.NilCipherID, err
	}

	// Create RotationRequest with its ID
	reqID := messages.NewRotationRequestID()
	req := &messages.RotationRequest{reqID, sessionID, cipherID, k, rotIdx}
	var reply *messages.RotationReply

	// Create channel before sending request to root.
	replyChan := make(chan *messages.RotationReply, 1)
	service.rotationRepLock.Lock()
	service.rotationReplies[reqID] = replyChan
	service.rotationRepLock.Unlock()

	// Send request to owner of the ciphertext
	log.Lvl2(service.ServerIdentity(), "Sending RotationRequest to owner of ciphertext:", reqID)
	err := service.SendRaw(cipherID.GetServerIdentityOwner(), req)
	if err != nil {
		err = errors.New("Couldn't send RotationRequest to owner: " + err.Error())
		log.Error(service.ServerIdentity(), "(ReqID =", reqID, ")\n", err)
		return messages.NilCipherID, err
	}

	// Wait on channel with timeout
	timeout := 1000 * time.Second
	log.Lvl2(service.ServerIdentity(), "(ReqID =", reqID, ")\n", "Sent GetRotationRequest to root. Waiting on channel to receive reply...")
	select {
	case reply = <-replyChan:
		log.Lvl3(service.ServerIdentity(), "(ReqID =", reqID, ")\n", "Got reply from channel")
	case <-time.After(timeout):
		err := errors.New("Did not receive reply from channel")
		log.Fatal(service.ServerIdentity(), "(ReqID =", reqID, ")\n", err)
		return messages.NilCipherID, err // Just not to see the warning
	}

	// Close channel
	log.Lvl3(service.ServerIdentity(), "(ReqID =", reqID, ")\n", "Received reply from channel. Closing it.")
	service.rotationRepLock.Lock()
	close(replyChan)
	delete(service.rotationReplies, reqID)
	service.rotationRepLock.Unlock()

	log.Lvl3(service.ServerIdentity(), "(ReqID =", reqID, ")\n", "Closed channel")

	if !reply.Valid {
		err := errors.New("Received invalid reply: owner couldn't perform rotation")
		log.Error(service.ServerIdentity(), "(ReqID =", reqID, ")\n", err)

		return messages.NilCipherID, err
	}

	log.Lvl3(service.ServerIdentity(), "(ReqID =", reqID, ")\n", "Received valid reply from channel:", reply.NewCipherID)

	return reply.NewCipherID, nil
}

// The RotationRequest is received by the owner of the ciphertext.
func (service *Service) processRotationRequest(msg *network.Envelope) {
	req := (msg.Msg).(*messages.RotationRequest)

	log.Lvl1(service.ServerIdentity(), "(ReqID =", req.ReqID, ")\n", "Received RotationRequest for ciphertext")

	// Start by declaring reply with minimal fields.
	reply := &messages.RotationReply{SessionID: req.SessionID, ReqID: req.ReqID, Valid: false}

	// Rotate the ciphertext
	log.Lvl3(service.ServerIdentity(), "(ReqID =", req.ReqID, ")\n", "Going to rotate the ciphertext")
	newCipherID, err := service.rotateCipher(req.ReqID.String(), req.SessionID, req.CipherID, req.RotIdx, req.K)
	if err != nil {
		log.Error(service.ServerIdentity(), "(ReqID =", req.ReqID, ")\n", "Could not rotate the ciphertext:", err)
	} else {
		log.Lvl3(service.ServerIdentity(), "(ReqID =", req.ReqID, ")\n", "Successfully rotated the ciphertext")
	}

	// Set fields in reply
	reply.Valid = (err == nil)
	reply.NewCipherID = newCipherID

	// Send reply to server
	log.Lvl2(service.ServerIdentity(), "(ReqID =", req.ReqID, ")\n", "Sending reply to server")
	err = service.SendRaw(msg.ServerIdentity, reply)
	if err != nil {
		log.Error(service.ServerIdentity(), "(ReqID =", req.ReqID, ")\n", "Could not reply to server:", err)
		return
	}
	log.Lvl3(service.ServerIdentity(), "(ReqID =", req.ReqID, ")\n", "Sent reply to server")

	return
}

// Rotates the ciphertext indexed by its ID.
// reqID is just a prefix for logs.
func (service *Service) rotateCipher(reqID string, sessionID messages.SessionID, cipherID messages.CipherID,
	rotIdx int, k uint64) (messages.CipherID, error) {
	log.Lvl2(service.ServerIdentity(), "(ReqID =", reqID, ")\n", "Rotate a ciphertext")

	// Extract Session, if existent
	s, ok := service.GetSessionService().GetSession(sessionID)
	if !ok {
		err := errors.New("Requested session does not exist")
		log.Error(service.ServerIdentity(), "(ReqID =", reqID, ")\n", err)
		return messages.NilCipherID, err
	}

	// Retrieve ciphertext
	log.Lvl3(service.ServerIdentity(), "(ReqID =", reqID, ")\n", "Retrieving ciphertext")
	ct, ok := s.GetCiphertext(cipherID)
	if !ok {
		err := errors.New("Ciphertext does not exist.")
		log.Error(service.ServerIdentity(), "(ReqID =", reqID, ")\n", err)
		return messages.NilCipherID, err
	}
	// Retrieving rotation key
	log.Lvl3(service.ServerIdentity(), "(ReqID =", reqID, ")\n", "Retrieving rotation key")
	// The rotation key is modifiable, but it is the pointer s.rotationKey itself that changes, not its content
	rotKey, ok := s.GetRotationKey(rotIdx, k)
	if !ok {
		err := errors.New("Could not retrieve rotation key")
		log.Error(service.ServerIdentity(), "(ReqID =", reqID, ")\n", err)
		return messages.NilCipherID, err
	}

	// Rotate

	// Reduce K modulo n/2 (each row is long n/2)
	k &= (1 << (s.Params.LogN - 1)) - 1

	// Only left-rotation is available. If right-rotation is requested, transform it into a left-rotation.
	if rotIdx == bfv.RotationRight {
		rotIdx = bfv.RotationLeft
		k = (1 << (s.Params.LogN - 1)) - k
	}

	log.Lvl3(service.ServerIdentity(), "(ReqID =", reqID, ")\n", "Rotating the ciphertext")
	eval := bfv.NewEvaluator(s.Params)
	var ctRot *bfv.Ciphertext
	switch bfv.Rotation(rotIdx) {
	case bfv.RotationRow:
		ctRot = eval.RotateRowsNew(ct, rotKey)
	case bfv.RotationLeft:
		ctRot = eval.RotateColumnsNew(ct, k, rotKey)
	}

	// Store locally
	log.Lvl3(service.ServerIdentity(), "(ReqID =", reqID, ")\n", "Storing the result")
	rotID := s.StoreCiphertextNewID(ctRot)

	return rotID, nil
}

// The RotationReply is received by the server which sent the request. This method only sends the reply through the
// channel on which DelegateRotateCipher is waiting.
func (service *Service) processRotationReply(msg *network.Envelope) {
	reply := (msg.Msg).(*messages.RotationReply)

	log.Lvl2(service.ServerIdentity(), "(ReqID =", reply.ReqID, ")\n", "Received RotationReply")

	// Get reply channel
	service.rotationRepLock.RLock()
	log.Lvl3(service.ServerIdentity(), "(ReqID =", reply.ReqID, ")\n", "Locked RotationRepLock")
	replyChan, ok := service.rotationReplies[reply.ReqID]
	service.rotationRepLock.RUnlock()

	// Send reply through channel
	if !ok {
		log.Fatal("Reply channel does not exist:", reply.ReqID)
	}
	log.Lvl2(service.ServerIdentity(), "(ReqID =", reply.ReqID, ")\n", "Sending reply through channel")
	replyChan <- reply

	log.Lvl2(service.ServerIdentity(), "(ReqID =", reply.ReqID, ")\n", "Sent reply through channel")

	return
}

// Legacy query
func (service *Service) HandleRotationQuery(query *messages.RotationQuery) (network.Message, error) {
	log.Lvl1(service.ServerIdentity(), "Received RotationQuery for ciphertext:", query.CipherID)

	rotID, err := service.rotateCipher("query", query.SessionID, query.CipherID, query.RotIdx, query.K)
	return &messages.RotationResponse{rotID, err == nil}, err
}
