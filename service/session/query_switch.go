package session

import (
	"errors"
	"github.com/ldsec/lattigo/bfv"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
	"lattigo-smc/protocols"
	"lattigo-smc/service/messages"
)

// Handler for reception of SwitchQuery from client.
func (service *Service) HandleSwitchQuery(query *messages.SwitchQuery) (network.Message, error) {
	log.Lvl1(service.ServerIdentity(), "Received SwitchQuery for ciphertext:", query.CipherID)

	switchedCipher, err := service.switchCipher("query", query.SessionID, query.PublicKey, query.CipherID)
	return &messages.SwitchResponse{switchedCipher, err == nil}, err
}

// Switches the ciphertext indexed by the ID.
// reqID is just a prefix for logs.
func (service *Service) switchCipher(reqID string, sessionID messages.SessionID, pk *bfv.PublicKey,
	cipherID messages.CipherID) (*bfv.Ciphertext, error) {
	log.Lvl2(service.ServerIdentity(), "(ReqID =", reqID, ")\n", "Public-key-switch a ciphertext")

	// Extract Session, if existent
	s, ok := service.sessions.GetSession(sessionID)
	if !ok {
		err := errors.New("Requested session does not exist")
		log.Error(service.ServerIdentity(), "(ReqID =", reqID, ")\n", err)
		return nil, err
	}

	// Retrieve ciphertext
	log.Lvl3(service.ServerIdentity(), "(ReqID =", reqID, ")\n", "Retrieving ciphertext")
	ct, ok := s.GetCiphertext(cipherID)
	if !ok {
		err := errors.New("Ciphertext does not exist.")
		log.Error(service.ServerIdentity(), "(ReqID =", reqID, ")\n", err)
		return nil, err
	}

	// Perform the PublicKeySwitchProtocol to switch the ciphertext

	// Create configuration for the protocol instance
	log.Lvl3(service.ServerIdentity(), "(ReqID =", reqID, ")\n", "Creating the configuration")
	config := &messages.SwitchConfig{sessionID, pk, ct}
	data, err := config.MarshalBinary()
	if err != nil {
		log.Error(service.ServerIdentity(), "(SessionID =", sessionID, ")\n", "Could not marshal protocol configuration:", err)
		return nil, err
	}
	conf := onet.GenericConfig{data}

	// Create TreeNodeInstance as root
	tree := s.Roster.GenerateNaryTreeWithRoot(2, service.ServerIdentity())
	if tree == nil {
		err := errors.New("Could not create tree")
		log.Error(service.ServerIdentity(), "(SessionID =", sessionID, ")\n", err)
		return nil, err
	}
	tni := service.NewTreeNodeInstance(tree, tree.Root, protocols.CollectivePublicKeySwitchingProtocolName)
	err = tni.SetConfig(&conf)
	if err != nil {
		log.Error(service.ServerIdentity(), "(SessionID =", sessionID, ")\n", "Could not set config:", err)
		return nil, err
	}

	// Instantiate protocol
	log.Lvl3(service.ServerIdentity(), "(SessionID =", sessionID, ")\n", "Instantiating protocol")
	protocol, err := service.NewProtocol(tni, &conf)
	if err != nil {
		log.Error(service.ServerIdentity(), "Could not instantiate protocol", err)
		return nil, err
	}

	// Register protocol instance
	log.Lvl3(service.ServerIdentity(), "(ReqID =", reqID, ")\n", "Registering PCKS protocol instance")
	err = service.RegisterProtocolInstance(protocol)
	if err != nil {
		log.Error(service.ServerIdentity(), "(ReqID =", reqID, ")\n", "Could not register protocol instance:", err)
		return nil, err
	}

	pcks := protocol.(*protocols.CollectivePublicKeySwitchingProtocol)

	// Start the protocol
	log.Lvl2(service.ServerIdentity(), "(ReqID =", reqID, ")\n", "Starting PCKS protocol")
	err = pcks.Start()
	if err != nil {
		log.Error(service.ServerIdentity(), "(ReqID =", reqID, ")\n", "Could not start PCKS protocol:", err)
		return nil, err
	}
	// Call dispatch (the main logic)
	log.Lvl2(service.ServerIdentity(), "(ReqID =", reqID, ")\n", "Dispatching protocol")
	err = pcks.Dispatch()
	if err != nil {
		log.Error(service.ServerIdentity(), "(ReqID =", reqID, ")\n", "Could not dispatch PCKS protocol:", err)
		return nil, err
	}

	// Wait for termination of protocol
	log.Lvl2(pcks.ServerIdentity(), "(ReqID =", reqID, ")\n", "Waiting for PCKS protocol to terminate...")
	pcks.WaitDone()

	log.Lvl2(service.ServerIdentity(), "(ReqID =", reqID, ")\n", "Switched ciphertext!")

	// Done with the protocol

	// Do not store locally

	return &pcks.CiphertextOut, nil
}
