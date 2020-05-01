package session

import (
	"github.com/ldsec/lattigo/bfv"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
	"lattigo-smc/service/messages"
)

func (service *Service) GetRemoteEvalKey(sessionID messages.SessionID, owner *network.ServerIdentity) (*bfv.EvaluationKey, bool) {
	log.Lvl2(service.ServerIdentity(), "Retrieving remote evaluation key")

	// Create GetEvalKeyRequest with its ID
	reqID := messages.NewGetEvalKeyRequestID()
	req := &messages.GetEvalKeyRequest{reqID, sessionID}

	// Create channel before sending request to root.
	service.getEvalKeyRepLock.Lock()
	service.getEvalKeyReplies[reqID] = make(chan *messages.GetEvalKeyReply)
	service.getEvalKeyRepLock.Unlock()

	// Send request to root
	log.Lvl2(service.ServerIdentity(), "Sending GetEvalKeyRequest to owner")
	err := service.SendRaw(owner, req)
	if err != nil {
		log.Error(service.ServerIdentity(), "Couldn't send GetEvalKeyRequest to root:", err)
		return nil, false
	}

	// Receive reply from channel
	log.Lvl3(service.ServerIdentity(), "Sent GetEvalKeyRequest to root. Waiting on channel to receive reply...")
	service.getEvalKeyRepLock.RLock()
	replyChan := service.getEvalKeyReplies[reqID]
	service.getEvalKeyRepLock.RUnlock()
	reply := <-replyChan // TODO: timeout if owner cannot send reply

	// Close channel
	log.Lvl3(service.ServerIdentity(), "Received reply from channel. Closing it.")
	service.getEvalKeyRepLock.Lock()
	close(replyChan)
	delete(service.getEvalKeyReplies, reqID)
	service.getEvalKeyRepLock.Unlock()

	log.Lvl4(service.ServerIdentity(), "Closed channel, returning")

	return reply.EvaluationKey, reply.Valid
}

func (service *Service) processGetEvalKeyRequest(msg *network.Envelope) {
	req := (msg.Msg).(*messages.GetEvalKeyRequest)

	log.Lvl2(service.ServerIdentity(), "Root. Received GetEvalKeyRequest.")

	// Start by declaring reply with minimal fields.
	reply := &messages.GetEvalKeyReply{req.ReqID, nil, false}

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

	// Get Evaluation Key
	s.evalKeyLock.RLock()
	evk := s.evalKey
	s.evalKeyLock.RUnlock()

	// Check existence
	if evk == nil {
		log.Error(service.ServerIdentity(), "Evaluation key not generated")
		reply.EvaluationKey = nil
		reply.Valid = false
	} else {
		reply.EvaluationKey = evk
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

// This method is executed at the server when receiving the root's GetEvalKeyReply.
// It simply sends the reply through the channel.
func (service *Service) processGetEvalKeyReply(msg *network.Envelope) {
	reply := (msg.Msg).(*messages.GetEvalKeyReply)

	log.Lvl2(service.ServerIdentity(), "Received GetEvalKeyReply:", reply.ReqID)

	// Simply send reply through channel
	service.getEvalKeyRepLock.RLock()
	service.getEvalKeyReplies[reply.ReqID] <- reply
	service.getEvalKeyRepLock.RUnlock()
	log.Lvl4(service.ServerIdentity(), "Sent reply through channel")

	return
}
