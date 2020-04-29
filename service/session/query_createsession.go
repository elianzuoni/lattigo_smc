// The goal of the CreateSession query is to create a new Session

package session

import (
	"errors"
	"github.com/ldsec/lattigo/bfv"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
	"lattigo-smc/service/messages"
	"lattigo-smc/service/protocols"
)

func (service *Service) HandleCreateSessionQuery(query *messages.CreateSessionQuery) (network.Message, error) {
	log.Lvl1(service.ServerIdentity(), "Received CreateSessionQuery")

	/*
		// Create CreateSessionRequest with its ID
		reqID := messages.NewCreateSessionRequestID()
		req := &messages.CreateSessionRequest{reqID, query}

		// Create channel before sending request to root.
		service.createSessionRepLock.Lock()
		service.createSessionReplies[reqID] = make(chan *messages.CreateSessionReply)
		service.createSessionRepLock.Unlock()

		// Send request to root
		log.Lvl2(service.ServerIdentity(), "Sending CreateSessionRequest to root")
		tree := query.Roster.GenerateBinaryTree() // This way, the root is implied in the Roster itself. TODO: ok?
		err := service.SendRaw(tree.Root.ServerIdentity, req)
		if err != nil {
			err = errors.New("Couldn't send CreateSessionRequest to root: " + err.Error())
			log.Error(err)
			return nil, err
		}

		log.Lvl3(service.ServerIdentity(), "Forwarded request to the root")

		// Receive reply from channel
		log.Lvl3(service.ServerIdentity(), "Sent CreateSessionRequest to root. Waiting on channel to receive reply...")
		service.createSessionRepLock.RLock()
		replyChan := service.createSessionReplies[reqID]
		service.createSessionRepLock.RUnlock()
		reply := <-replyChan // TODO: timeout if root cannot send reply

		// Close channel
		log.Lvl3(service.ServerIdentity(), "Received reply from channel. Closing it.")
		service.createSessionRepLock.Lock()
		close(replyChan)
		delete(service.createSessionReplies, reqID)
		service.createSessionRepLock.Unlock()

		log.Lvl4(service.ServerIdentity(), "Closed channel, returning")

		return &messages.CreateSessionResponse{reply.SessionID, reply.Valid}, nil

	*/

	// Decide the SessionID (it has to be uniquely identifying across the system, so we generate it here)
	sessionID := messages.NewSessionID()

	// Launch the CreateSession protocol, to create the Session at all nodes
	err := service.createSession(sessionID, query.Roster, query.Params)
	if err != nil {
		log.Error(service.ServerIdentity(), "Could not create session:", err)
		return nil, err
	}

	return &messages.CreateSessionResponse{sessionID, true}, nil
}

/*
func (service *Service) processCreateSessionRequest(msg *network.Envelope) {
	req := (msg.Msg).(*messages.CreateSessionRequest)

	log.Lvl1(service.ServerIdentity(), "Root. Received CreateSessionRequest.")

	// Start by declaring reply with minimal fields.
	reply := &messages.CreateSessionReply{ReqID: req.ReqID, Valid: false}

	// Decide the SessionID (it has to be uniquely identifying across the system, so we generate it here)
	sessionID := messages.NewSessionID()

	// Launch the CreateSession protocol, to create the Session at all nodes
	err := service.createSession(sessionID, req.Query.Roster, req.Query.Params)
	if err != nil {
		log.Error(service.ServerIdentity(), "Could not create session:", err)
		err = service.SendRaw(msg.ServerIdentity, reply)
		if err != nil {
			log.Error(service.ServerIdentity(), "Could not reply (negatively) to server:", err)
		}

		return
	}

	// Send reply to server
	reply.SessionID = sessionID
	reply.Valid = true
	log.Lvl2(service.ServerIdentity(), "Sending positive reply to server")
	err = service.SendRaw(msg.ServerIdentity, reply)
	if err != nil {
		log.Error("Could not reply (positively) to server:", err)
	}
	log.Lvl4(service.ServerIdentity(), "Sent positive reply to server")

	return
}

*/

// Creates a session at all nodes, launching the CreateSession protocol (establishes itself as the root for the session).
func (service *Service) createSession(SessionID messages.SessionID, roster *onet.Roster, params *bfv.Parameters) error {
	log.Lvl2(service.ServerIdentity(), "Creating a session")

	// Create TreeNodeInstance as root
	tree := roster.GenerateNaryTreeWithRoot(2, service.ServerIdentity())
	if tree == nil {
		err := errors.New("Could not create tree")
		log.Error(service.ServerIdentity(), err)
		return err
	}
	tni := service.NewTreeNodeInstance(tree, tree.Root, CreateSessionProtocolName)

	// Create configuration for the protocol instance
	config := &messages.CreateSessionConfig{SessionID, roster, service.ServerIdentity(), params}
	data, err := config.MarshalBinary()
	if err != nil {
		log.Error(service.ServerIdentity(), "Could not marshal protocol configuration:", err)
		return err
	}

	// Instantiate protocol
	log.Lvl3(service.ServerIdentity(), "Instantiating create-session protocol")
	protocol, err := service.NewProtocol(tni, &onet.GenericConfig{data})
	if err != nil {
		log.Error(service.ServerIdentity(), "Could not instantiate create-session protocol", err)
		return err
	}
	// Register protocol instance
	log.Lvl3(service.ServerIdentity(), "Registering create-session protocol instance")
	err = service.RegisterProtocolInstance(protocol)
	if err != nil {
		log.Error(service.ServerIdentity(), "Could not register protocol instance:", err)
		return err
	}

	csp := protocol.(*protocols.CreateSessionProtocol)

	// Start the protocol
	log.Lvl2(service.ServerIdentity(), "Starting create-session protocol")
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
	log.Lvl2(csp.ServerIdentity(), "Waiting for create-session protocol to terminate...")
	csp.WaitDone()
	// At this point, the session has been created

	log.Lvl2(service.ServerIdentity(), "Created Session!")

	return nil
}

/*
// This method is executed at the server when receiving the root's CreateSessionReply.
// It simply sends the reply through the channel.
func (service *Service) processCreateSessionReply(msg *network.Envelope) {
	reply := (msg.Msg).(*messages.CreateSessionReply)

	log.Lvl1(service.ServerIdentity(), "Received CreateSessionReply:", reply.ReqID)

	// Simply send reply through channel
	service.createSessionRepLock.RLock()
	service.createSessionReplies[reply.ReqID] <- reply
	service.createSessionRepLock.RUnlock()
	log.Lvl4(service.ServerIdentity(), "Sent reply through channel")

	return
}

*/
