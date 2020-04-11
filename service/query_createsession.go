// The goal of the CreateSession query is to create a new Session

package service

import (
	"errors"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
	"lattigo-smc/utils"
)

func (smc *Service) HandleCreateSessionQuery(query *CreateSessionQuery) (network.Message, error) {
	log.Lvl1(smc.ServerIdentity(), "Received CreateSessionQuery")

	// Create CreateSessionRequest with its ID
	reqID := newCreateSessionRequestID()
	req := &CreateSessionRequest{reqID, query}

	// Create channel before sending request to root.
	smc.createSessionRepLock.Lock()
	smc.createSessionReplies[reqID] = make(chan *CreateSessionReply)
	smc.createSessionRepLock.Unlock()

	// Send request to root
	log.Lvl2(smc.ServerIdentity(), "Sending CreateSessionRequest to root")
	tree := query.Roster.GenerateBinaryTree() // This way, the root is implied in the Roster itself. TODO: ok?
	err := smc.SendRaw(tree.Root.ServerIdentity, req)
	if err != nil {
		err = errors.New("Couldn't send CreateSessionRequest to root: " + err.Error())
		log.Error(err)
		return nil, err
	}

	log.Lvl3(smc.ServerIdentity(), "Forwarded request to the root")

	// Receive reply from channel
	log.Lvl3(smc.ServerIdentity(), "Sent CreateSessionRequest to root. Waiting on channel to receive reply...")
	smc.createSessionRepLock.RLock()
	replyChan := smc.createSessionReplies[reqID]
	smc.createSessionRepLock.RUnlock()
	reply := <-replyChan // TODO: timeout if root cannot send reply

	// Close channel
	log.Lvl3(smc.ServerIdentity(), "Received reply from channel. Closing it.")
	smc.createSessionRepLock.Lock()
	close(replyChan)
	delete(smc.createSessionReplies, reqID)
	smc.createSessionRepLock.Unlock()

	log.Lvl4(smc.ServerIdentity(), "Closed channel, returning")

	return &CreateSessionResponse{reply.SessionID, reply.Valid}, nil
}

func (smc *Service) processCreateSessionRequest(msg *network.Envelope) {
	req := (msg.Msg).(*CreateSessionRequest)

	log.Lvl1(smc.ServerIdentity(), "Root. Received CreateSessionRequest.")

	// Start by declaring reply with minimal fields.
	reply := &CreateSessionReply{ReqID: req.ReqID, Valid: false}

	// Decide the SessionID (it has to be uniquely identifying across the system, so we generate it here)
	sessionID := newSessionID()
	// Create the broadcast message
	broad := &CreateSessionBroadcast{req.ReqID, sessionID, req.Query}

	// Create channel before sending broadcast.
	smc.createSessionBroadcastAnswers[req.ReqID] = make(chan *CreateSessionBroadcastAnswer)

	// Broadcast the message so that all nodes can create the session.
	log.Lvl2(smc.ServerIdentity(), "Broadcasting message to all nodes")
	err := utils.Broadcast(smc.ServiceProcessor, req.Query.Roster, broad)
	if err != nil {
		log.Error(smc.ServerIdentity(), "Could not broadcast message:", err)
		err = smc.SendRaw(msg.ServerIdentity, reply)
		if err != nil {
			log.Error(smc.ServerIdentity(), "Could not reply (negatively) to server:", err)
		}

		return
	}

	// Wait for all their answers. For now, they can only be positive
	log.Lvl2(smc.ServerIdentity(), "Waiting for nodes' answers")
	answers := 0
	for answers < len(req.Query.Roster.List) {
		// TODO: timeout if servers do not answer
		// We don't care about the content of the answer, it is surely positive
		_ = <-smc.createSessionBroadcastAnswers[req.ReqID]
		answers += 1
		log.Lvl4(smc.ServerIdentity(), "Received", answers, "answers")
	}
	// TODO: close channel?

	log.Lvl3(smc.ServerIdentity(), "Received all answers")

	// Send reply to server
	reply.SessionID = sessionID
	reply.Valid = true
	log.Lvl2(smc.ServerIdentity(), "Sending positive reply to server")
	err = smc.SendRaw(msg.ServerIdentity, reply)
	if err != nil {
		log.Error("Could not reply (positively) to server:", err)
	}
	log.Lvl4(smc.ServerIdentity(), "Sent positive reply to server")

	return
}

func (smc *Service) processCreateSessionBroadcast(msg *network.Envelope) {
	broad := msg.Msg.(*CreateSessionBroadcast)

	log.Lvl1(smc.ServerIdentity(), "Received CreateSessionBroadcast")

	// Create session as required
	log.Lvl3(smc.ServerIdentity(), "Creating session")
	session := smc.NewSession(broad.SessionID, broad.Query.Roster, broad.Query.Params)

	// Register session
	smc.sessionsLock.Lock()
	smc.sessions[broad.SessionID] = session
	smc.sessionsLock.Unlock()

	// Answer to root
	answer := &CreateSessionBroadcastAnswer{broad.ReqID, true}
	log.Lvl2(smc.ServerIdentity(), "Sending answer to root")
	err := smc.SendRaw(msg.ServerIdentity, answer)
	if err != nil {
		log.Error("Could not answer to root:", err)
	}
	log.Lvl4(smc.ServerIdentity(), "Sent answer to root")

	return
}

func (smc *Service) processCreateSessionBroadcastAnswer(msg *network.Envelope) {
	answer := (msg.Msg).(*CreateSessionBroadcastAnswer)

	log.Lvl1(smc.ServerIdentity(), "Received CreateSessionBroadcastAnswer:", answer.ReqID)

	// Simply send answer through channel
	smc.createSessionBroadcastAnswers[answer.ReqID] <- answer
	log.Lvl4(smc.ServerIdentity(), "Sent answer through channel")

	return
}

// This method is executed at the server when receiving the root's CreateSessionReply.
// It simply sends the reply through the channel.
func (smc *Service) processCreateSessionReply(msg *network.Envelope) {
	reply := (msg.Msg).(*CreateSessionReply)

	log.Lvl1(smc.ServerIdentity(), "Received CreateSessionReply:", reply.ReqID)

	// Simply send reply through channel
	smc.createSessionRepLock.RLock()
	smc.createSessionReplies[reply.ReqID] <- reply
	smc.createSessionRepLock.RUnlock()
	log.Lvl4(smc.ServerIdentity(), "Sent reply through channel")

	return
}
