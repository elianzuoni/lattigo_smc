package service

import (
	"errors"
	"github.com/ldsec/lattigo/bfv"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
	"lattigo-smc/protocols"
	"lattigo-smc/utils"
)

func (s *Service) HandleSharesToEncQuery(query *SharesToEncQuery) (network.Message, error) {
	log.Lvl1(s.ServerIdentity(), "Received SharesToEncQuery for ciphertext:", query.CipherID)

	// Create SharesToEncRequest with its ID
	reqID := newSharesToEncRequestID()
	req := SharesToEncRequest{reqID, query}

	// Create channel before sending request to root.
	s.sharesToEncReplies[reqID] = make(chan *SharesToEncReply)

	// Send request to root
	log.Lvl2(s.ServerIdentity(), "Sending SharesToEncRequest to root:", reqID)
	tree := s.Roster.GenerateBinaryTree()
	err := s.SendRaw(tree.Root.ServerIdentity, req)
	if err != nil {
		err = errors.New("Couldn't send SharesToEncRequest to root: " + err.Error())
		log.Error(err)
		return nil, err
	}

	// Receive reply from channel
	log.Lvl3(s.ServerIdentity(), "Forwarded request to the root. Waiting to receive reply...")
	reply := <-s.sharesToEncReplies[reqID] // TODO: timeout if root cannot send reply
	if !reply.valid {
		err := errors.New("Received invalid reply: root couldn't perform shares-to-enc")
		log.Error(s.ServerIdentity(), err)
		// Respond with the reply, not nil, err
	}
	log.Lvl4(s.ServerIdentity(), "Received valid reply from channel")
	// TODO: close channel?

	return &SharesToEncResponse{reply.valid}, nil
}

func (s *Service) processSharesToEncRequest(msg *network.Envelope) {
	log.Lvl1(s.ServerIdentity(), "Root. Received SharesToEncRequest.")

	req := (msg.Msg).(*SharesToEncRequest)
	reply := SharesToEncReply{SharesToEncRequestID: req.SharesToEncRequestID}

	// The check for existence of the share is done in the protocol factory, since it is a problem of every node

	// Build preparation message to broadcast
	prep := SharesToEncBroadcast{req.SharesToEncRequestID,
		&S2EParameters{req.CipherID}}

	// First, broadcast the request so that all nodes can be ready for the subsequent protocol.
	log.Lvl2(s.ServerIdentity(), "Broadcasting preparation message to all nodes")
	err := utils.Broadcast(s.ServiceProcessor, &s.Roster, prep)
	if err != nil {
		log.Error(s.ServerIdentity(), "Could not broadcast preparation message:", err)
		err = s.SendRaw(msg.ServerIdentity, reply) // Field valid stays false
		if err != nil {
			log.Error(s.ServerIdentity(), "Could not reply (negatively) to server:", err)
		}

		return
	}

	// Then, launch the shares-to-enc protocol to get the re-encrypted ciphertext
	log.Lvl2(s.ServerIdentity(), "Re-encrypting ciphertext")
	ctReenc, err := s.reencryptCiphertext()
	if err != nil {
		log.Error(s.ServerIdentity(), "Could not perform shares-to-enc:", err)
		err := s.SendRaw(msg.ServerIdentity, reply) // Field valid stays false
		if err != nil {
			log.Error(s.ServerIdentity(), "Could not reply (negatively) to server:", err)
		}
		return
	}

	// Register (overwrite) in the local database
	s.database[req.CipherID] = ctReenc

	log.Lvl3(s.ServerIdentity(), "Successfully re-encrypted ciphertext")

	// Set fields in the reply
	reply.valid = true

	// Send the positive reply to the server
	log.Lvl2(s.ServerIdentity(), "Replying (positively) to server")
	err = s.SendRaw(msg.ServerIdentity, reply)
	if err != nil {
		log.Error(s.ServerIdentity(), "Could not reply (positively) to server")
		return
	}

	return
}

func (s *Service) processSharesToEncBroadcast(msg *network.Envelope) {
	log.Lvl1(s.ServerIdentity(), "Received SetupBroadcast")

	prep := msg.Msg.(*SharesToEncBroadcast)

	// Send the shares-to-enc parameters through the channel, on which the protocol factory waits
	log.Lvl3(s.ServerIdentity(), "Sending sharesToEnc parameters through channel")
	s.sharesToEncParams <- prep.params

	log.Lvl4(s.ServerIdentity(), "Sent sharesToEnc parameters through channel")

	return
}

func (s *Service) reencryptCiphertext() (*bfv.Ciphertext, error) {
	log.Lvl2(s.ServerIdentity(), "Sharing a ciphertext")

	// TODO: is all this really needed? Is there an equivalent of CreateProtocol?
	// Instantiate protocol
	log.Lvl3(s.ServerIdentity(), "Instantiating shares-to-enc protocol")
	tree := s.Roster.GenerateBinaryTree()
	tni := s.NewTreeNodeInstance(tree, tree.Root, SharesToEncProtocolName)
	protocol, err := s.NewProtocol(tni, nil)
	if err != nil {
		log.Error(s.ServerIdentity(), "Could not instantiate shares-to-enc protocol", err)
		return nil, err
	}
	// Register protocol instance
	log.Lvl3(s.ServerIdentity(), "Registering shares-to-enc protocol instance")
	err = s.RegisterProtocolInstance(protocol)
	if err != nil {
		log.Error(s.ServerIdentity(), "Could not register protocol instance:", err)
		return nil, err
	}

	s2e := protocol.(*protocols.SharesToEncryptionProtocol)

	// Start the protocol
	log.Lvl2(s.ServerIdentity(), "Starting shares-to-enc protocol")
	err = s2e.Start()
	if err != nil {
		log.Error(s.ServerIdentity(), "Could not start shares-to-enc protocol:", err)
		return nil, err
	}
	// Call dispatch (the main logic)
	err = s2e.Dispatch()
	if err != nil {
		log.Error(s.ServerIdentity(), "Could not dispatch shares-to-enc protocol:", err)
		return nil, err
	}

	// Wait for termination of protocol
	log.Lvl2(s2e.ServerIdentity(), "Waiting for shares-to-enc protocol to terminate...")
	ctReenc := <-s2e.ChannelCiphertext
	// At this point, the protocol finaliser has already registered the share in the shares database

	log.Lvl2(s.ServerIdentity(), "Shared ciphertext!")

	return ctReenc, nil
}

func (s *Service) processSharesToEncReply(msg *network.Envelope) {
	reply := (msg.Msg).(*SharesToEncReply)

	log.Lvl1(s.ServerIdentity(), "Received SharesToEncReply")

	// Simply send reply through channel
	s.sharesToEncReplies[reply.SharesToEncRequestID] <- reply
	log.Lvl4(s.ServerIdentity(), "Sent reply through channel")

	return
}
