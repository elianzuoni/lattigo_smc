package session

import (
	"github.com/ldsec/lattigo/bfv"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
	"lattigo-smc/service/messages"
)

func (service *Service) GetRemoteRotationKey(sessionID messages.SessionID, rotIdx int, k uint64,
	owner *network.ServerIdentity) (*bfv.RotationKeys, bool) {
	log.Lvl2(service.ServerIdentity(), "Retrieving remote rotation key")

	// Create GetRotKeyRequest with its ID
	reqID := messages.NewGetRotKeyRequestID()
	req := &messages.GetRotKeyRequest{reqID, sessionID, rotIdx, k}

	// Create channel before sending request to root.
	service.getRotKeyRepLock.Lock()
	service.getRotKeyReplies[reqID] = make(chan *messages.GetRotKeyReply)
	service.getRotKeyRepLock.Unlock()

	// Send request to root
	log.Lvl2(service.ServerIdentity(), "Sending GetRotKeyRequest to root")
	err := service.SendRaw(owner, req)
	if err != nil {
		log.Error(service.ServerIdentity(), "Couldn't send GetRotKeyRequest to root:", err)
		return nil, false
	}

	// Receive reply from channel
	log.Lvl3(service.ServerIdentity(), "Sent GetRotKeyRequest to root. Waiting on channel to receive reply...")
	service.getRotKeyRepLock.RLock()
	replyChan := service.getRotKeyReplies[reqID]
	service.getRotKeyRepLock.RUnlock()
	reply := <-replyChan // TODO: timeout if owner cannot send reply

	// Close channel
	log.Lvl3(service.ServerIdentity(), "Received reply from channel. Closing it.")
	service.getRotKeyRepLock.Lock()
	close(replyChan)
	delete(service.getRotKeyReplies, reqID)
	service.getRotKeyRepLock.Unlock()

	log.Lvl4(service.ServerIdentity(), "Closed channel, returning")

	return reply.RotationKey, reply.Valid
}

func (service *Service) processGetRotKeyRequest(msg *network.Envelope) {
	req := (msg.Msg).(*messages.GetRotKeyRequest)

	log.Lvl2(service.ServerIdentity(), "Root. Received GetRotKeyRequest.")

	// Start by declaring reply with minimal fields.
	reply := &messages.GetRotKeyReply{req.ReqID, nil, false}

	// Extract Session, if existent
	s, ok := service.sessions.GetSession(req.SessionID)
	if !ok {
		log.Error(service.ServerIdentity(), "Requested session does not exist")
		err := service.SendRaw(msg.ServerIdentity, reply)
		if err != nil {
			log.Error(service.ServerIdentity(), "Could not reply (negatively) to server:", err)
		}

		return
	}

	// Reduce K modulo n/2 (each row is long n/2)
	req.K &= (1 << (s.Params.LogN - 1)) - 1

	// Only left-rotation is available. If right-rotation is requested, transform it into a left-rotation.
	if req.RotIdx == bfv.RotationRight {
		req.RotIdx = bfv.RotationLeft
		req.K = (1 << (s.Params.LogN - 1)) - req.K
	}

	// Get Rotation Key
	s.rotKeyLock.RLock()
	rotk := s.rotationKey
	s.rotKeyLock.RUnlock()

	// Check existence, and set fields in the reply
	if rotk == nil {
		log.Error(service.ServerIdentity(), "Rotation key not generated")
		reply.RotationKey = nil
		reply.Valid = false
	} else if req.RotIdx == bfv.RotationRow && !rotk.CanRotateRows() {
		log.Error(service.ServerIdentity(), "Cannot rotate rows")
		reply.RotationKey = nil
		reply.Valid = false
	} else if req.RotIdx == bfv.RotationLeft && !rotk.CanRotateLeft(req.K, uint64(1<<s.Params.LogN)) {
		log.Error(service.ServerIdentity(), "Cannot rotate columns of specified amount")
		reply.RotationKey = nil
		reply.Valid = false
	} else {
		reply.RotationKey = rotk
		reply.Valid = true
	}

	// Send reply to server
	log.Lvl2(service.ServerIdentity(), "Sending reply to server")
	err := service.SendRaw(msg.ServerIdentity, reply)
	if err != nil {
		log.Error("Could not reply to server:", err)
		return
	}
	log.Lvl4(service.ServerIdentity(), "Sent positive reply to server")

	return
}

/*
func (service *Service) closeSession(SessionID messages.SessionID) error {
	log.Lvl2(service.ServerIdentity(), "Closing a session")

	// Extract session
	s, ok := service.sessions.GetSession(SessionID)
	if !ok {
		err := errors.New("Requested session does not exist")
		log.Error(service.ServerIdentity(), err)
		return err
	}

	// Create TreeNodeInstance as root
	tree := s.Roster.GenerateNaryTreeWithRoot(2, service.ServerIdentity())
	if tree == nil {
		err := errors.New("Could not create tree")
		log.Error(service.ServerIdentity(), err)
		return err
	}
	tni := service.NewTreeNodeInstance(tree, tree.Root, CloseSessionProtocolName)

	// Create configuration for the protocol instance
	config := &messages.CloseSessionConfig{SessionID}
	data, err := config.MarshalBinary()
	if err != nil {
		log.Error(service.ServerIdentity(), "Could not marshal protocol configuration:", err)
		return err
	}

	// Instantiate protocol
	log.Lvl3(service.ServerIdentity(), "Instantiating close-session protocol")
	protocol, err := service.NewProtocol(tni, &onet.GenericConfig{data})
	if err != nil {
		log.Error(service.ServerIdentity(), "Could not instantiate create-session protocol", err)
		return err
	}
	// Register protocol instance
	log.Lvl3(service.ServerIdentity(), "Registering close-session protocol instance")
	err = service.RegisterProtocolInstance(protocol)
	if err != nil {
		log.Error(service.ServerIdentity(), "Could not register protocol instance:", err)
		return err
	}

	csp := protocol.(*protocols.CloseSessionProtocol)

	// Start the protocol
	log.Lvl2(service.ServerIdentity(), "Starting close-session protocol")
	err = csp.Start()
	if err != nil {
		log.Error(service.ServerIdentity(), "Could not start enc-to-shares protocol:", err)
		return err
	}
	// Call dispatch (the main logic)
	err = csp.Dispatch()
	if err != nil {
		log.Error(service.ServerIdentity(), "Could not dispatch enc-to-shares protocol:", err)
		return err
	}

	// Wait for termination of protocol
	log.Lvl2(csp.ServerIdentity(), "Waiting for close-session protocol to terminate...")
	csp.WaitDone()
	// At this point, the session has been closed

	log.Lvl2(service.ServerIdentity(), "Closed Session!")

	return nil
}

*/

// This method is executed at the server when receiving the root's GetRotKeyReply.
// It simply sends the reply through the channel.
func (service *Service) processGetRotKeyReply(msg *network.Envelope) {
	reply := (msg.Msg).(*messages.GetRotKeyReply)

	log.Lvl2(service.ServerIdentity(), "Received GetRotKeyReply:", reply.ReqID)

	// Simply send reply through channel
	service.getRotKeyRepLock.RLock()
	service.getRotKeyReplies[reply.ReqID] <- reply
	service.getRotKeyRepLock.RUnlock()
	log.Lvl4(service.ServerIdentity(), "Sent reply through channel")

	return
}
