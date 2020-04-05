// The goal of the CloseSession query is to close an existing Session

package service

import (
	"errors"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
	"lattigo-smc/utils"
)

func (smc *Service) HandleCloseSessionQuery(query *CloseSessionQuery) (network.Message, error) {
	log.Lvl1(smc.ServerIdentity(), "Received CloseSessionQuery")

	// Extract Session, if existent
	s, ok := smc.sessions[query.SessionID]
	if !ok {
		err := errors.New("Requested session does not exist")
		log.Error(smc.ServerIdentity(), err)
		return nil, err
	}

	// Create CloseSessionRequest with its ID
	reqID := newCloseSessionRequestID()
	req := &CloseSessionRequest{reqID, query.SessionID, query}

	// Create channel before sending request to root.
	smc.closeSessionReplies[reqID] = make(chan *CloseSessionReply)

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
	reply := <-smc.closeSessionReplies[reqID] // TODO: timeout if root cannot send reply

	log.Lvl4(smc.ServerIdentity(), "Received reply from channel")
	// TODO: close channel?

	return &CloseSessionResponse{reply.Valid}, nil
}

func (smc *Service) processCloseSessionRequest(msg *network.Envelope) {
	req := (msg.Msg).(*CloseSessionRequest)

	log.Lvl1(smc.ServerIdentity(), "Root. Received CloseSessionRequest.")

	// Start by declaring reply with minimal fields.
	reply := &CloseSessionReply{ReqID: req.ReqID, Valid: false}

	// Extract Session, if existent
	s, ok := smc.sessions[req.SessionID]
	if !ok {
		log.Error(smc.ServerIdentity(), "Requested session does not exist")
		// Send negative response
		err := smc.SendRaw(msg.ServerIdentity, reply)
		if err != nil {
			log.Error("Could not send reply:", err)
		}
		return
	}

	// Create the broadcast message
	broad := &CloseSessionBroadcast{req.ReqID, req.Query}

	// Broadcast the message so that all nodes can delete the session.
	log.Lvl2(smc.ServerIdentity(), "Broadcasting message to all nodes")
	err := utils.Broadcast(smc.ServiceProcessor, s.Roster, broad)
	if err != nil {
		log.Error(smc.ServerIdentity(), "Could not broadcast message:", err)
		err = smc.SendRaw(msg.ServerIdentity, reply)
		if err != nil {
			log.Error(smc.ServerIdentity(), "Could not reply (negatively) to server:", err)
		}

		return
	}

	// Wait for all their answers. If anyone is negative, the response is negative
	log.Lvl2(smc.ServerIdentity(), "Waiting for nodes' answers")
	answers := 0
	valid := true
	for answers < len(s.Roster.List) {
		// TODO: timeout if servers do not answer
		ans := <-smc.closeSessionBroadcastAnswers[req.ReqID]
		answers += 1
		if !ans.Valid {
			valid = false
		}
		log.Lvl4(smc.ServerIdentity(), "Received", answers, "answers")
	}
	// TODO: close channel?

	log.Lvl3(smc.ServerIdentity(), "Received all answers")

	// Send reply to server
	reply.Valid = valid
	log.Lvl2(smc.ServerIdentity(), "Sending reply to server")
	err = smc.SendRaw(msg.ServerIdentity, reply)
	if err != nil {
		log.Error("Could not reply to server:", err)
	}
	log.Lvl4(smc.ServerIdentity(), "Sent positive reply to server")

	return
}

func (smc *Service) processCloseSessionBroadcast(msg *network.Envelope) {
	broad := msg.Msg.(*CloseSessionBroadcast)

	log.Lvl1(smc.ServerIdentity(), "Received CloseSessionBroadcast")

	// Start by declaring answer with default fields
	answer := &CloseSessionBroadcastAnswer{ReqID: broad.ReqID}

	// Check if requested session exists, and set the field "Valid"
	_, ok := smc.sessions[broad.Query.SessionID]
	if ok {
		// Delete session as required
		log.Lvl3(smc.ServerIdentity(), "Requested session exists. Deleting it")
		delete(smc.sessions, broad.Query.SessionID)
		answer.Valid = true
	} else {
		// Mark answer as invalid
		log.Lvl3(smc.ServerIdentity(), "Requested session does not exist. Returning invalid answer")
		answer.Valid = false
	}

	// Answer to root
	log.Lvl2(smc.ServerIdentity(), "Sending answer to root")
	err := smc.SendRaw(msg.ServerIdentity, answer)
	if err != nil {
		log.Error("Could not answer to server:", err)
	}
	log.Lvl4(smc.ServerIdentity(), "Sent answer to server")

	return
}

func (smc *Service) processCloseSessionBroadcastAnswer(msg *network.Envelope) {
	answer := (msg.Msg).(*CloseSessionBroadcastAnswer)

	log.Lvl1(smc.ServerIdentity(), "Received CloseSessionBroadcastAnswer:", answer.ReqID)

	// Simply send answer through channel
	smc.closeSessionBroadcastAnswers[answer.ReqID] <- answer
	log.Lvl4(smc.ServerIdentity(), "Sent answer through channel")

	return
}

// This method is executed at the server when receiving the root's CloseSessionReply.
// It simply sends the reply through the channel.
func (smc *Service) processCloseSessionReply(msg *network.Envelope) {
	reply := (msg.Msg).(*CloseSessionReply)

	log.Lvl1(smc.ServerIdentity(), "Received CloseSessionReply:", reply.ReqID)

	// Simply send reply through channel
	smc.closeSessionReplies[reply.ReqID] <- reply
	log.Lvl4(smc.ServerIdentity(), "Sent reply through channel")

	return
}