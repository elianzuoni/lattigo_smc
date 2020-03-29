// This file defines the behaviour when receiving a RelinQuery from client.
// HandleRelinQuery forwards the query to the root, and immediately returns the same ID as in the request,
// since the root will store the relinearised ciphertext under the same ID.
// The root executes processSumRequest, which checks whether the requested ciphertext exists and the
// evaluation key was generated, then, if possible, relinearises the ciphertext and stores it back with the same ID.

package service

import (
	"github.com/ldsec/lattigo/bfv"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
)

// Handles the client's SumQuery. Forwards the query to root, and immediately returns the same ID, without
// waiting a response from the root.	// TODO: wait to see if ciphertext exists
func (s *Service) HandleRelinearisationQuery(query *RelinQuery) (network.Message, error) {
	log.Lvl1(s.ServerIdentity(), "Server. Received RelinQuery for ciphertext:", query.ID)

	// Create RelinRequest
	req := (*RelinRequest)(query)

	// Send request to root
	log.Lvl2(s.ServerIdentity(), "Sending RelinRequest to root.")
	tree := s.Roster.GenerateBinaryTree()
	err := s.SendRaw(tree.Root.ServerIdentity, req)
	if err != nil {
		log.Error(s.ServerIdentity(), "Couldn't send RelinRequest to root: ", err.Error)
		return nil, err
	}

	// Directly return the same ID, since the root will store the relinearised ciphertext
	// under the same ID.
	// TODO: what if the ciphertext does not exist?
	return &ServiceState{query.ID, false}, nil

}

// This method is executed at the root when receiving a RelinRequest.
// It checks for feasibility (whether or not it possesses the requested ciphertext and the evaluation key);
// if possible, it relinearises the requested ciphertext, then stores it back with the same ID.
// The server knows this, so there is no need to send a reply.
func (s *Service) processRelinRequest(msg *network.Envelope) {
	req := (msg.Msg).(*RelinRequest)

	log.Lvl1(s.ServerIdentity(), "Root. Received RelinRequest for ciphertext", req.ID)

	// Check feasibility
	log.Lvl3(s.ServerIdentity(), "Checking existence of ciphertext and evaluation key")
	ct, ok := s.database[req.ID]
	if !ok {
		log.Error(s.ServerIdentity(), "Requested ciphertext does not exist:", req.ID)
		return
	}
	if !s.evalKeyGenerated {
		log.Error(s.ServerIdentity(), "Evaluation key not generated")
		return
	}

	// Relinearise
	log.Lvl3(s.ServerIdentity(), "Relinearising ciphertext")
	eval := bfv.NewEvaluator(s.Params)
	ctRelin := eval.RelinearizeNew(ct, s.EvaluationKey)

	// Register (overwrite) in local database
	s.database[req.ID] = ctRelin

	return
}
