package service

import (
	"errors"
	"github.com/ldsec/lattigo/bfv"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
	"lattigo-smc/protocols"
	"lattigo-smc/utils"
)

func (s *Service) HandleRefreshQuery(query *RefreshQuery) (network.Message, error) {
	log.Lvl1(s.ServerIdentity(), "Received RefreshQuery for ciphertext:", query.CipherID)

	// Create RefreshRequest with its ID
	reqID := newRefreshRequestID()
	req := RefreshRequest{reqID, query}

	// Create channel before sending request to root.
	s.refreshReplies[reqID] = make(chan *RefreshReply)

	// Send request to root
	log.Lvl2(s.ServerIdentity(), "Sending RefreshRequest to root:", reqID)
	tree := s.Roster.GenerateBinaryTree()
	err := s.SendRaw(tree.Root.ServerIdentity, req)
	if err != nil {
		err = errors.New("Couldn't send RefreshRequest to root: " + err.Error())
		log.Error(err)
		return nil, err
	}

	// Receive reply from channel
	log.Lvl3(s.ServerIdentity(), "Forwarded request to the root. Waiting to receive reply...")
	reply := <-s.refreshReplies[reqID] // TODO: timeout if root cannot send reply
	if !reply.Valid {
		err := errors.New("Received invalid reply: root couldn't perform refresh")
		log.Error(s.ServerIdentity(), err)
		// Respond with the reply, not nil, err
	}
	log.Lvl4(s.ServerIdentity(), "Received valid reply from channel")
	// TODO: close channel?

	return &RefreshResponse{reply.Valid}, nil
}

func (s *Service) processRefreshRequest(msg *network.Envelope) {
	log.Lvl1(s.ServerIdentity(), "Root. Received RefreshRequest.")

	req := (msg.Msg).(*RefreshRequest)
	reply := RefreshReply{ReqID: req.ReqID}

	// Check existence of ciphertext
	ct, ok := s.database[req.Query.CipherID]
	if !ok {
		log.Error(s.ServerIdentity(), "Ciphertext", req.Query.CipherID, "does not exist.")
		err := s.SendRaw(msg.ServerIdentity, reply) // Field valid stays false
		if err != nil {
			log.Error(s.ServerIdentity(), "Could not reply (negatively) to server:", err)
		}

		return
	}

	// Build preparation message to broadcast
	prep := RefreshBroadcast{req.ReqID, ct}

	// First, broadcast the request so that all nodes can be ready for the subsequent protocol.
	log.Lvl2(s.ServerIdentity(), "Broadcasting preparation message to all nodes")
	err := utils.Broadcast(s.ServiceProcessor, s.Roster, prep)
	if err != nil {
		log.Error(s.ServerIdentity(), "Could not broadcast preparation message:", err)
		err = s.SendRaw(msg.ServerIdentity, reply) // Field valid stays false
		if err != nil {
			log.Error(s.ServerIdentity(), "Could not reply (negatively) to server:", err)
		}

		return
	}

	// Then, launch the refresh protocol to get the refreshed ciphertext
	log.Lvl2(s.ServerIdentity(), "Refreshing ciphertext")
	ctRefresh, err := s.refreshCiphertext()
	if err != nil {
		log.Error(s.ServerIdentity(), "Could not perform refresh:", err)
		err := s.SendRaw(msg.ServerIdentity, reply) // Field valid stays false
		if err != nil {
			log.Error(s.ServerIdentity(), "Could not reply (negatively) to server:", err)
		}
		return
	}

	// Register (overwrite) in the local database
	s.database[req.Query.CipherID] = ctRefresh

	log.Lvl3(s.ServerIdentity(), "Successfully refreshed ciphertext")

	// Set fields in the reply
	reply.Valid = true

	// Send the positive reply to the server
	log.Lvl2(s.ServerIdentity(), "Replying (positively) to server")
	err = s.SendRaw(msg.ServerIdentity, reply)
	if err != nil {
		log.Error(s.ServerIdentity(), "Could not reply (positively) to server")
		return
	}

	return
}

func (s *Service) processRefreshBroadcast(msg *network.Envelope) {
	log.Lvl1(s.ServerIdentity(), "Received SetupBroadcast")

	prep := msg.Msg.(*RefreshBroadcast)

	// Send the refresh parameters through the channel, on which the protocol factory waits
	log.Lvl3(s.ServerIdentity(), "Sending refresh parameters through channel")
	s.refreshParams <- prep.Ciphertext

	log.Lvl4(s.ServerIdentity(), "Sent refresh parameters through channel")

	return
}

func (s *Service) refreshCiphertext() (*bfv.Ciphertext, error) {
	log.Lvl2(s.ServerIdentity(), "Performing refresh")

	// TODO: is all this really needed? Is there an equivalent of CreateProtocol?
	// Instantiate protocol
	log.Lvl3(s.ServerIdentity(), "Instantiating refresh protocol")
	tree := s.Roster.GenerateBinaryTree()
	tni := s.NewTreeNodeInstance(tree, tree.Root, protocols.CollectiveRefreshName)
	protocol, err := s.NewProtocol(tni, nil)
	if err != nil {
		log.Error(s.ServerIdentity(), "Could not instantiate refresh protocol", err)
		return nil, err
	}
	// Register protocol instance
	log.Lvl3(s.ServerIdentity(), "Registering refresh protocol instance")
	err = s.RegisterProtocolInstance(protocol)
	if err != nil {
		log.Error(s.ServerIdentity(), "Could not register refresh protocol instance:", err)
		return nil, err
	}

	refresh := protocol.(*protocols.RefreshProtocol)

	// Start the protocol
	log.Lvl2(s.ServerIdentity(), "Starting refresh protocol")
	err = refresh.Start()
	if err != nil {
		log.Error(s.ServerIdentity(), "Could not start refresh protocol:", err)
		return nil, err
	}
	// Call dispatch (the main logic)
	err = refresh.Dispatch()
	if err != nil {
		log.Error(s.ServerIdentity(), "Could not dispatch refresh protocol:", err)
		return nil, err
	}

	// Wait for termination of protocol
	log.Lvl2(refresh.ServerIdentity(), "Waiting for refresh protocol to terminate...")
	refresh.WaitDone()

	log.Lvl2(s.ServerIdentity(), "Refreshed ciphertext!")

	return &refresh.Ciphertext, nil
}

func (s *Service) processRefreshReply(msg *network.Envelope) {
	reply := (msg.Msg).(*RefreshReply)

	log.Lvl1(s.ServerIdentity(), "Received RefreshReply")

	// Simply send reply through channel
	s.refreshReplies[reply.ReqID] <- reply
	log.Lvl4(s.ServerIdentity(), "Sent reply through channel")

	return
}
