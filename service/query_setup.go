// The goal of the setup query is to have the root generate the specified keys.

package service

import (
	"errors"
	"github.com/ldsec/lattigo/bfv"
	"github.com/ldsec/lattigo/dbfv"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
	"lattigo-smc/protocols"
	"lattigo-smc/utils"
)

func (s *Service) HandleSetupQuery(query *SetupQuery) (network.Message, error) {
	log.Lvl1("Received SetupQuery")

	// Create SumRequest with its ID
	reqID := newSetupRequestID()
	req := SetupRequest{reqID, query}

	// Create channel before sending request to root.
	s.setupReplies[reqID] = make(chan *SetupReply)

	// Send request to root
	log.Lvl2(s.ServerIdentity(), "Sending SetupRequest to root:", reqID)
	tree := s.Roster.GenerateBinaryTree()
	err := s.SendRaw(tree.Root.ServerIdentity, req)
	if err != nil {
		err = errors.New("Couldn't send SetupRequest to root: " + err.Error())
		log.Error(err)
		return nil, err
	}

	log.Lvl3(s.ServerIdentity(), "Forwarded request to the root")

	// Receive reply from channel
	log.Lvl3(s.ServerIdentity(), "Sent SetupRequest to root. Waiting on channel to receive reply...")
	reply := <-s.setupReplies[reqID] // TODO: timeout if root cannot send reply

	log.Lvl4(s.ServerIdentity(), "Received reply from channel")
	// TODO: close channel?

	return &SetupResponse{
		PubKeyGenerated:  reply.pubKeyGenerated,
		EvalKeyGenerated: reply.evalKeyGenerated,
		RotKeyGenerated:  reply.rotKeyGenerated,
	}, nil
}

func (s *Service) processSetupRequest(msg *network.Envelope) {
	log.Lvl1(s.ServerIdentity(), "Root. Received SetupRequest.")

	req := (msg.Msg).(*SetupRequest)
	reply := SetupReply{SetupRequestID: req.SetupRequestID}

	// First, broadcast the request so that all nodes can be ready for the subsequent protocols.
	log.Lvl2(s.ServerIdentity(), "Broadcasting preparation message to all nodes")
	prep := (*SetupBroadcast)(req)
	err := utils.Broadcast(s.ServiceProcessor, &req.Roster, prep)
	if err != nil {
		log.Error(s.ServerIdentity(), "Could not broadcast preparation message:", err)
		// TODO: maybe not return anything and let it timeout?
		err = s.SendRaw(msg.ServerIdentity, reply) // Flag fields stay false
		if err != nil {
			log.Error(s.ServerIdentity(), "Could not reply (negatively) to server:", err)
		}

		return
	}

	// Then, generate the requested keys (if missing)
	if req.GeneratePublicKey && !s.pubKeyGenerated {
		log.Lvl3(s.ServerIdentity(), "PublicKey requested and missing. Generating it.")

		err = s.genPublicKey()
		if err != nil {
			log.Error(s.ServerIdentity(), "Could not generate public key:", err)
		} else {
			s.pubKeyGenerated = true
			reply.pubKeyGenerated = true
		}
	}
	if req.GenerateEvaluationKey && !s.evalKeyGenerated {
		log.Lvl3(s.ServerIdentity(), "EvaluationKey requested and missing. Generating it.")

		err = s.genEvalKey()
		if err != nil {
			log.Error(s.ServerIdentity(), "Could not generate evaluation key:", err)
		} else {
			s.evalKeyGenerated = true
			reply.evalKeyGenerated = true
		}
	}
	if req.GenerateRotationKey && !s.rotKeyGenerated {
		log.Lvl3(s.ServerIdentity(), "RotationKey requested and missing. Generating it.")

		err = s.genRotKey()
		if err != nil {
			log.Error(s.ServerIdentity(), "Could not generate rotation key:", err)
		} else {
			s.rotKeyGenerated = true
			reply.rotKeyGenerated = true
		}
	}

	log.Lvl3(s.ServerIdentity(), "Generated requested (and missing) keys")

	// Send reply to server
	log.Lvl2(s.ServerIdentity(), "Sending positive reply to server")
	err = s.SendRaw(msg.ServerIdentity, reply)
	if err != nil {
		log.Error("Could not reply (positively) to server:", err)
	}
	log.Lvl4(s.ServerIdentity(), "Sent positive reply to server")

	return
}

func (s *Service) processSetupBroadcast(msg *network.Envelope) {
	log.Lvl1(s.ServerIdentity(), "Received SetupBroadcast")

	prep := msg.Msg.(*SetupBroadcast) // This message prepares for the subsequent protocol

	// Set parameters, if needed, and signal this on the appropriate locks
	// TODO: this assumes that the first setup query is not just for rotation
	if !s.skSet && (prep.GeneratePublicKey || prep.GenerateEvaluationKey || prep.GenerateRotationKey) {
		log.Lvl3(s.ServerIdentity(), "skShard not yet set. Generating from request")
		s.Roster = prep.Roster
		s.Params = bfv.DefaultParams[prep.ParamsIdx]
		keygen := bfv.NewKeyGenerator(s.Params)
		s.skShard = keygen.GenSecretKey()
		s.partialPk = keygen.GenPublicKey(s.skShard)
		s.crpGen = dbfv.NewCRPGenerator(s.Params, prep.Seed)
		s.cipherCRPgen = dbfv.NewCipherCRPGenerator(s.Params, prep.Seed)

		log.Lvl3(s.ServerIdentity(), "Unlocking locks for CKG and EKG protocol factories")
		s.waitCKG.Unlock()
		s.waitEKG.Unlock()

		s.skSet = true
	}
	if !s.rotParamsSet && prep.GenerateRotationKey {
		log.Lvl3(s.ServerIdentity(), "Rotation parameters not yet set. Generating from request")
		s.rotIdx = prep.RotIdx
		s.k = prep.K

		log.Lvl3(s.ServerIdentity(), "Unlocking lock for RKG protocol factory")
		s.waitRKG.Unlock()

		s.rotParamsSet = true
	}

	return
}

func (s *Service) genPublicKey() error {
	log.Lvl1(s.ServerIdentity(), "Root. Generating PublicKey")

	// TODO: is all this really needed? Is there an equivalent of CreateProtocol?
	// Instantiate protocol
	log.Lvl3(s.ServerIdentity(), "Instantiating CKG protocol")
	tree := s.Roster.GenerateBinaryTree()
	tni := s.NewTreeNodeInstance(tree, tree.Root, protocols.CollectiveKeyGenerationProtocolName)
	protocol, err := s.NewProtocol(tni, nil)
	if err != nil {
		log.Error(s.ServerIdentity(), "Could not instantiate CKG protocol", err)
		return err
	}
	// Register protocol instance
	log.Lvl3(s.ServerIdentity(), "Registering CKG protocol instance")
	err = s.RegisterProtocolInstance(protocol)
	if err != nil {
		log.Error(s.ServerIdentity(), "Could not register protocol instance:", err)
		return err
	}

	ckgp := protocol.(*protocols.CollectiveKeyGenerationProtocol)

	// Start the protocol
	log.Lvl2(s.ServerIdentity(), "Starting CKG protocol")
	err = ckgp.Start()
	if err != nil {
		log.Error(s.ServerIdentity(), "Could not start CKG protocol:", err)
		return err
	}
	// Call dispatch (the main logic)
	err = ckgp.Dispatch()
	if err != nil {
		log.Error(s.ServerIdentity(), "Could not dispatch CKG protocol:", err)
		return err
	}

	// Wait for termination of protocol
	log.Lvl2(ckgp.ServerIdentity(), "Waiting for CKG protocol to terminate...")
	ckgp.Wait()

	// Retrieve PublicKey
	s.MasterPublicKey = ckgp.Pk
	s.pubKeyGenerated = true
	log.Lvl1(s.ServerIdentity(), "Retrieved PublicKey!")

	return nil
}

func (s *Service) genEvalKey() error {
	log.Lvl1(s.ServerIdentity(), "Root. Generating EvaluationKey (relinearisation key).")

	// TODO: is all this really needed? Is there an equivalent of CreateProtocol?
	// Instantiate protocol
	log.Lvl3(s.ServerIdentity(), "Instantiating EKG protocol")
	tree := s.Roster.GenerateBinaryTree()
	tni := s.NewTreeNodeInstance(tree, tree.Root, protocols.RelinearizationKeyProtocolName)
	protocol, err := s.NewProtocol(tni, nil)
	if err != nil {
		log.Error(s.ServerIdentity(), "Could not instantiate EKG protocol", err)
		return err
	}
	// Register protocol instance
	log.Lvl3(s.ServerIdentity(), "Registering EKG protocol instance")
	err = s.RegisterProtocolInstance(protocol)
	if err != nil {
		log.Error(s.ServerIdentity(), "Could not register protocol instance:", err.Error)
		return err
	}

	ekg := protocol.(*protocols.RelinearizationKeyProtocol)

	log.Lvl2(s.ServerIdentity(), "Starting EKG protocol")
	err = ekg.Start()
	if err != nil {
		log.Error(s.ServerIdentity(), "Could not start EKG protocol:", err.Error)
		return err
	}
	// Call dispatch (the main logic)
	err = ekg.Dispatch()
	if err != nil {
		log.Error(s.ServerIdentity(), "Could not dispatch EKG protocol:", err.Error)
		return err
	}

	// Wait for termination of protocol
	log.Lvl2(ekg.ServerIdentity(), "Waiting for EKG protocol to terminate...")
	ekg.Wait()

	// Retrieve EvaluationKey
	s.evalKey = ekg.EvaluationKey
	s.evalKeyGenerated = true
	log.Lvl1(s.ServerIdentity(), "Retrieved EvaluationKey!")

	return nil
}

func (s *Service) genRotKey() error {
	log.Lvl1(s.ServerIdentity(), "Root. Generating RotationKey.")

	// TODO: is all this really needed? Is there an equivalent of CreateProtocol?
	// Instantiate protocol
	log.Lvl3(s.ServerIdentity(), "Instantiating RKG protocol")
	tree := s.Roster.GenerateBinaryTree()
	tni := s.NewTreeNodeInstance(tree, tree.Root, protocols.RotationProtocolName)
	protocol, err := s.NewProtocol(tni, nil)
	if err != nil {
		log.Error(s.ServerIdentity(), "Could not instantiate RKG protocol", err)
		return err
	}
	// Register protocol instance
	log.Lvl3(s.ServerIdentity(), "Registering RKG protocol instance")
	err = s.RegisterProtocolInstance(protocol)
	if err != nil {
		log.Error(s.ServerIdentity(), "Could not register protocol instance:", err.Error)
		return err
	}

	rkg := protocol.(*protocols.RotationKeyProtocol)

	log.Lvl2(s.ServerIdentity(), "Starting RKG protocol")
	err = rkg.Start()
	if err != nil {
		log.Error(s.ServerIdentity(), "Could not start RKG protocol:", err.Error)
		return err
	}
	// Call dispatch (the main logic)
	err = rkg.Dispatch()
	if err != nil {
		log.Error(s.ServerIdentity(), "Could not dispatch RKG protocol:", err.Error)
		return err
	}

	// Wait for termination of protocol
	log.Lvl2(rkg.ServerIdentity(), "Waiting for RKG protocol to terminate...")
	rkg.Wait()

	// Retrieve RotationKey
	s.rotationKey = &rkg.RotKey
	s.rotKeyGenerated = true
	log.Lvl1(s.ServerIdentity(), "Retrieved RotationKey!")

	return nil
}

// This method is executed at the server when receiving the root's SetupReply.
// It simply sends the reply through the channel.
func (s *Service) processSetupReply(msg *network.Envelope) {
	reply := (msg.Msg).(*SetupReply)

	log.Lvl1(s.ServerIdentity(), "Received SetupReply:", reply.SetupRequestID)

	// Simply send reply through channel
	s.setupReplies[reply.SetupRequestID] <- reply
	log.Lvl4(s.ServerIdentity(), "Sent reply through channel")

	return
}
