// The goal of the Store Query is to store a new ciphertext into the system. The root decides its CipherID.

package service

import (
	"errors"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
)

// HandleStoreQuery is the handler registered for message type StoreQuery:
// a client asks to store new data into the system.
// The server forwards the request to the root, which stores the ciphertext and assigns it a CipherID which is returned
// in the reply.
func (s *Service) HandleStoreQuery(query *StoreQuery) (network.Message, error) {
	log.Lvl1(s.ServerIdentity(), "Received StoreRequest query")

	// Create SumRequest with its ID
	reqID := newStoreRequestID()
	req := StoreRequest{reqID, query}

	// Create channel before sending request to root.
	s.storeReplies[reqID] = make(chan *StoreReply)

	// Send request to root
	log.Lvl2(s.ServerIdentity(), "Sending StoreRequest to the root")
	tree := s.Roster.GenerateBinaryTree()
	err := s.SendRaw(tree.Root.ServerIdentity, req)
	if err != nil {
		err = errors.New("Couldn't send StoreRequest to the root: " + err.Error())
		log.Error(s.ServerIdentity(), err)
		return nil, err
	}

	// Receive reply from channel
	log.Lvl3(s.ServerIdentity(), "Sent StoreRequest to root. Waiting on channel to receive reply...")
	reply := <-s.storeReplies[reqID] // TODO: timeout if root cannot send reply

	log.Lvl4(s.ServerIdentity(), "Received reply from channel:", reply.CipherID)
	// TODO: close channel?

	return &StoreResponse{reply.CipherID}, nil
}

// StoreRequest is received at root from server.
// The ciphertext is stored under a fresh CipherID, which is returned in the reply.
func (s *Service) processStoreRequest(msg *network.Envelope) {
	req := (msg.Msg).(*StoreRequest)
	log.Lvl1(s.ServerIdentity(), "Root. Received forwarded request to store new ciphertext")

	// Register in local database
	newCipherID := newCipherID()
	s.database[newCipherID] = req.Query.Ciphertext

	// Send reply to server
	log.Lvl2(s.ServerIdentity(), "Sending positive reply to server")
	err := s.SendRaw(msg.ServerIdentity, &StoreReply{req.ReqID, newCipherID})
	if err != nil {
		log.Error("Could not reply (positively) to server:", err)
	}
	log.Lvl4(s.ServerIdentity(), "Sent positive reply to server")
}

// This method is executed at the server when receiving the root's StoreReply.
// It simply sends the reply through the channel.
func (s *Service) processStoreReply(msg *network.Envelope) {
	reply := (msg.Msg).(*StoreReply)

	log.Lvl1(s.ServerIdentity(), "Received StoreReply:", reply.ReqID)

	// Simply send reply through channel
	s.storeReplies[reply.ReqID] <- reply
	log.Lvl4(s.ServerIdentity(), "Sent reply through channel")

	return
}
