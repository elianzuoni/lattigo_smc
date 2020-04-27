// The goal of the CloseSession query is to close an existing Session

package service

import (
	"errors"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
	"lattigo-smc/service/messages"
	"lattigo-smc/utils"
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

	// Extract Session, if existent
	s, ok := smc.sessions.GetSession(req.SessionID)
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
	broad := &messages.CloseSessionBroadcast{req.ReqID, req.Query}

	// Create channel before sending broadcast.
	smc.closeSessionBroadcastAnswers[req.ReqID] = make(chan *messages.CloseSessionBroadcastAnswer)

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
	broad := msg.Msg.(*messages.CloseSessionBroadcast)

	log.Lvl1(smc.ServerIdentity(), "Received CloseSessionBroadcast")

	// Start by declaring answer with default fields
	answer := &messages.CloseSessionBroadcastAnswer{ReqID: broad.ReqID}

	// Check if requested session exists, and set the field "Valid"
	_, ok := smc.sessions.GetSession(broad.Query.SessionID)
	if ok {
		// Delete session as required
		log.Lvl3(smc.ServerIdentity(), "Requested session exists. Deleting it")
		smc.sessions.DeleteSession(broad.Query.SessionID)
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
	answer := (msg.Msg).(*messages.CloseSessionBroadcastAnswer)

	log.Lvl1(smc.ServerIdentity(), "Received CloseSessionBroadcastAnswer:", answer.ReqID)

	// Simply send answer through channel
	smc.closeSessionBroadcastAnswers[answer.ReqID] <- answer
	log.Lvl4(smc.ServerIdentity(), "Sent answer through channel")

	return
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
