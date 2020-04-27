// The goal of the CloseSession query is to close an existing Session

package service

import (
	"errors"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
	"lattigo-smc/service/messages"
	"lattigo-smc/service/protocols"
)

func (smc *Service) HandleCloseSessionQuery(query *messages.CloseSessionQuery) (network.Message, error) {
	log.Lvl1(smc.ServerIdentity(), "Received CloseSessionQuery")

	// Extract Session, if existent
	s, ok := smc.sessions.GetSession(query.SessionID)
	if !ok {
		err := errors.New("Requested session does not exist")
		log.Error(smc.ServerIdentity(), err)
		return nil, err
	}

	// Create CloseSessionRequest with its ID
	reqID := messages.NewCloseSessionRequestID()
	smc.closeSessionRepLock.Lock()
	req := &messages.CloseSessionRequest{reqID, query.SessionID, query}
	smc.closeSessionRepLock.Unlock()

	// Create channel before sending request to root.
	smc.closeSessionReplies[reqID] = make(chan *messages.CloseSessionReply)

	// Send request to root
	log.Lvl2(smc.ServerIdentity(), "Sending CloseSessionRequest to root")
	tree := s.Roster.GenerateBinaryTree()
	err := smc.SendRaw(tree.Root.ServerIdentity, req)
	if err != nil {
		err = errors.New("Couldn't send CloseSessionRequest to root: " + err.Error())
		log.Error(err)
		return nil, err
	}

	log.Lvl3(smc.ServerIdentity(), "Forwarded request to the root")

	// Receive reply from channel
	log.Lvl3(smc.ServerIdentity(), "Sent CloseSessionRequest to root. Waiting on channel to receive reply...")
	smc.closeSessionRepLock.RLock()
	replyChan := smc.closeSessionReplies[reqID]
	smc.closeSessionRepLock.RUnlock()
	reply := <-replyChan // TODO: timeout if root cannot send reply

	// Close channel
	log.Lvl3(smc.ServerIdentity(), "Received reply from channel. Closing it.")
	smc.closeSessionRepLock.Lock()
	close(replyChan)
	delete(smc.closeSessionReplies, reqID)
	smc.closeSessionRepLock.Unlock()

	log.Lvl4(smc.ServerIdentity(), "Closed channel, returning")

	return &messages.CloseSessionResponse{reply.Valid}, nil
}

func (smc *Service) processCloseSessionRequest(msg *network.Envelope) {
	req := (msg.Msg).(*messages.CloseSessionRequest)

	log.Lvl1(smc.ServerIdentity(), "Root. Received CloseSessionRequest.")

	// Start by declaring reply with minimal fields.
	reply := &messages.CloseSessionReply{ReqID: req.ReqID, Valid: false}

	// Launch the CloseSession protocol, to delete the Session at all nodes
	err := smc.closeSession(req.Query.SessionID)
	if err != nil {
		log.Error(smc.ServerIdentity(), "Could not close session:", err)
		err = smc.SendRaw(msg.ServerIdentity, reply)
		if err != nil {
			log.Error(smc.ServerIdentity(), "Could not reply (negatively) to server:", err)
		}

		return
	}

	// Send reply to server
	reply.Valid = true
	log.Lvl2(smc.ServerIdentity(), "Sending reply to server")
	err = smc.SendRaw(msg.ServerIdentity, reply)
	if err != nil {
		log.Error("Could not reply to server:", err)
	}
	log.Lvl4(smc.ServerIdentity(), "Sent positive reply to server")

	return
}

func (smc *Service) closeSession(SessionID messages.SessionID) error {
	log.Lvl2(smc.ServerIdentity(), "Closing a session")

	// Extract session
	s, ok := smc.sessions.GetSession(SessionID)
	if !ok {
		err := errors.New("Requested session does not exist")
		log.Error(smc.ServerIdentity(), err)
		return err
	}

	// Create TreeNodeInstance as root
	tree := s.Roster.GenerateNaryTreeWithRoot(2, smc.ServerIdentity())
	if tree == nil {
		err := errors.New("Could not create tree")
		log.Error(smc.ServerIdentity(), err)
		return err
	}
	tni := smc.NewTreeNodeInstance(tree, tree.Root, CloseSessionProtocolName)

	// Create configuration for the protocol instance
	config := &messages.CloseSessionConfig{SessionID}
	data, err := config.MarshalBinary()
	if err != nil {
		log.Error(smc.ServerIdentity(), "Could not marshal protocol configuration:", err)
		return err
	}

	// Instantiate protocol
	log.Lvl3(smc.ServerIdentity(), "Instantiating close-session protocol")
	protocol, err := smc.NewProtocol(tni, &onet.GenericConfig{data})
	if err != nil {
		log.Error(smc.ServerIdentity(), "Could not instantiate create-session protocol", err)
		return err
	}
	// Register protocol instance
	log.Lvl3(smc.ServerIdentity(), "Registering close-session protocol instance")
	err = smc.RegisterProtocolInstance(protocol)
	if err != nil {
		log.Error(smc.ServerIdentity(), "Could not register protocol instance:", err)
		return err
	}

	csp := protocol.(*protocols.CloseSessionProtocol)

	// Start the protocol
	log.Lvl2(smc.ServerIdentity(), "Starting close-session protocol")
	err = csp.Start()
	if err != nil {
		log.Error(smc.ServerIdentity(), "Could not start enc-to-shares protocol:", err)
		return err
	}
	// Call dispatch (the main logic)
	err = csp.Dispatch()
	if err != nil {
		log.Error(smc.ServerIdentity(), "Could not dispatch enc-to-shares protocol:", err)
		return err
	}

	// Wait for termination of protocol
	log.Lvl2(csp.ServerIdentity(), "Waiting for close-session protocol to terminate...")
	csp.WaitDone()
	// At this point, the session has been closed

	log.Lvl2(smc.ServerIdentity(), "Closed Session!")

	return nil
}

// This method is executed at the server when receiving the root's CloseSessionReply.
// It simply sends the reply through the channel.
func (smc *Service) processCloseSessionReply(msg *network.Envelope) {
	reply := (msg.Msg).(*messages.CloseSessionReply)

	log.Lvl1(smc.ServerIdentity(), "Received CloseSessionReply:", reply.ReqID)

	// Simply send reply through channel
	smc.closeSessionRepLock.RLock()
	smc.closeSessionReplies[reply.ReqID] <- reply
	smc.closeSessionRepLock.RUnlock()
	log.Lvl4(smc.ServerIdentity(), "Sent reply through channel")

	return
}
