package session

import (
	"errors"
	"github.com/ldsec/lattigo/bfv"
	"github.com/ldsec/lattigo/dbfv"
	"github.com/ldsec/lattigo/ring"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"lattigo-smc/protocols"
	"lattigo-smc/service/messages"
	serviceProto "lattigo-smc/service/protocols"
)

const CreateSessionProtocolName = "CreateSessionProtocol"
const CloseSessionProtocolName = "CloseSessionProtocol"

// Though we have NewProtocol, onet needs to register the protocol name. So we register dummy protocol factories.
func init() {
	_, _ = onet.GlobalProtocolRegister(CreateSessionProtocolName,
		func(tni *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
			return nil, nil
		})

	_, _ = onet.GlobalProtocolRegister(CloseSessionProtocolName,
		func(tni *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
			return nil, nil
		})
}

// NewProtocol starts a new protocol given by the name in the TreeNodeInstance, and returns it correctly initialised.
// It is able to do the initialisation because it has access to the service.
// Only gets called at children: root has to manually call it, register the instance, and dispatch it.
func (service *Service) NewProtocol(tni *onet.TreeNodeInstance, conf *onet.GenericConfig) (onet.ProtocolInstance, error) {
	var err error
	var protocol onet.ProtocolInstance = nil

	switch tni.ProtocolName() {
	case protocols.CollectiveKeyGenerationProtocolName:
		protocol, err = service.newProtoCKG(tni, conf)

	case protocols.RelinearizationKeyProtocolName:
		protocol, err = service.newProtoEKG(tni, conf)

	case protocols.RotationProtocolName:
		protocol, err = service.newProtoRKG(tni, conf)

	case CreateSessionProtocolName:
		protocol, err = service.newProtoCreateSession(tni, conf)

	case CloseSessionProtocolName:
		protocol, err = service.newProtoCloseSession(tni, conf)
	}

	if err != nil {
		return nil, err
	}
	return protocol, nil
}

// Public key generation

func (service *Service) newProtoCKG(tn *onet.TreeNodeInstance, cfg *onet.GenericConfig) (onet.ProtocolInstance, error) {
	log.Lvl1(service.ServerIdentity(), "CKG protocol factory")

	// First, extract configuration
	config := &messages.GenPubKeyConfig{}
	err := config.UnmarshalBinary(cfg.Data)
	if err != nil {
		log.Error(service.ServerIdentity(), "Could not extract protocol configuration:", err)
		return nil, err
	}

	// Then, extract session, if exists
	s, ok := service.sessions.GetSession(config.SessionID)
	if !ok {
		err = errors.New("Requested session does not exist")
		log.Error(service.ServerIdentity(), err)
		return nil, err
	}

	// Set the root of the tree (protocol initiator) as the key owner
	s.pubKeyOwnerLock.Lock()
	s.pubKeyOwner = tn.Root().ServerIdentity
	s.pubKeyOwnerLock.Unlock()

	// Instantiate protocol with incomplete constructor
	log.Lvl2(service.ServerIdentity(), "Instantiating protocol with incomplete constructor")
	protocol, err := protocols.NewCollectiveKeyGeneration(tn)
	if err != nil {
		log.Error(service.ServerIdentity(), "Could not instantiate protocol")
		return nil, err
	}
	ckgp := protocol.(*protocols.CollectiveKeyGenerationProtocol)

	// Generate the CRP
	crpGen := dbfv.NewCRPGenerator(s.Params, config.Seed)
	crp := crpGen.ClockNew()

	// Finally, initialise the rest of the fields
	log.Lvl3(service.ServerIdentity(), "Initialising protocol")
	err = ckgp.Init(s.Params, s.skShard, crp)
	if err != nil {
		log.Error(service.ServerIdentity(), "Could not initialise protocol")
		return nil, err
	}

	return ckgp, err
}

// Evaluation key generation

func (service *Service) newProtoEKG(tn *onet.TreeNodeInstance, cfg *onet.GenericConfig) (onet.ProtocolInstance, error) {
	log.Lvl2(service.ServerIdentity(), "EKG protocol factory")

	// First, extract configuration
	config := &messages.GenEvalKeyConfig{}
	err := config.UnmarshalBinary(cfg.Data)
	if err != nil {
		log.Error(service.ServerIdentity(), "Could not extract protocol configuration:", err)
		return nil, err
	}

	// Then, extract session, if exists
	s, ok := service.sessions.GetSession(config.SessionID)
	if !ok {
		err = errors.New("Requested session does not exist")
		log.Error(service.ServerIdentity(), err)
		return nil, err
	}

	// Set the root of the tree (protocol initiator) as the key owner
	s.evalKeyOwnerLock.Lock()
	s.evalKeyOwner = tn.Root().ServerIdentity
	s.evalKeyOwnerLock.Unlock()

	// Instantiate protocol with incomplete constructor
	log.Lvl2(service.ServerIdentity(), "Instantiating protocol with incomplete constructor")
	protocol, err := protocols.NewRelinearizationKey(tn)
	if err != nil {
		log.Error(service.ServerIdentity(), "Could not instantiate protocol")
		return nil, err
	}
	ekgp := protocol.(*protocols.RelinearizationKeyProtocol)

	// Generate the CRP
	crpGen := dbfv.NewCRPGenerator(s.Params, config.Seed)
	modulus := s.Params.Moduli.Qi
	crp := make([]*ring.Poly, len(modulus))
	for j := 0; j < len(modulus); j++ {
		crp[j] = crpGen.ClockNew()
	}

	// Finally, initialise the rest of the fields
	log.Lvl3(service.ServerIdentity(), "Initialising protocol")
	err = ekgp.Init(*s.Params, *s.skShard, crp)
	if err != nil {
		log.Error(service.ServerIdentity(), "Could not initialise protocol", err)
		return nil, err
	}

	return ekgp, nil
}

// Rotation key generation

func (service *Service) newProtoRKG(tn *onet.TreeNodeInstance, cfg *onet.GenericConfig) (onet.ProtocolInstance, error) {
	log.Lvl2(service.ServerIdentity(), "RKG protocol factory")

	// First, extract configuration
	config := &messages.GenRotKeyConfig{}
	err := config.UnmarshalBinary(cfg.Data)
	if err != nil {
		log.Error(service.ServerIdentity(), "Could not extract protocol configuration:", err)
		return nil, err
	}

	// Then, extract session, if exists
	s, ok := service.sessions.GetSession(config.SessionID)
	if !ok {
		err = errors.New("Requested session does not exist")
		log.Error(service.ServerIdentity(), err)
		return nil, err
	}

	// Set the root of the tree (protocol initiator) as the key owner
	s.rotKeyOwnerLock.Lock()
	s.rotKeyOwner = tn.Root().ServerIdentity
	s.rotKeyOwnerLock.Unlock()

	// Instantiate protocol with incomplete constructor
	log.Lvl2(service.ServerIdentity(), "Instantiating protocol with incomplete constructor")
	protocol, err := protocols.NewRotationKey(tn)
	if err != nil {
		log.Error(service.ServerIdentity(), "Could not instantiate protocol")
		return nil, err
	}
	rkgp := protocol.(*protocols.RotationKeyProtocol)

	// Generate the CRP
	crpGen := dbfv.NewCRPGenerator(s.Params, config.Seed)
	modulus := s.Params.Moduli.Qi
	crp := make([]*ring.Poly, len(modulus))
	for j := 0; j < len(modulus); j++ {
		crp[j] = crpGen.ClockNew()
	}

	// Finally, initialise the rest of the fields
	log.Lvl3(service.ServerIdentity(), "Initialising protocol")
	// No need to lock rotation key here. The root (which is the only one that uses it) has already locked it.
	err = rkgp.Init(s.Params, *s.skShard, s.rotationKey, bfv.Rotation(config.RotIdx), config.K, crp)
	if err != nil {
		log.Error(service.ServerIdentity(), "Could not initialise protocol", err)
		return nil, err
	}

	return rkgp, nil
}

// Create Session

func (service *Service) newProtoCreateSession(tn *onet.TreeNodeInstance, cfg *onet.GenericConfig) (onet.ProtocolInstance, error) {
	log.Lvl2(service.ServerIdentity(), "CreateSession protocol factory")

	// First, extract configuration
	config := &messages.CreateSessionConfig{}
	err := config.UnmarshalBinary(cfg.Data)
	if err != nil {
		log.Error(service.ServerIdentity(), "Could not extract protocol configuration:", err)
		return nil, err
	}

	// Then, create the protocol with the known parameters and the one just received
	p, err := serviceProto.NewCreateSessionProtocol(tn, service.sessions, config.SessionID, config.Roster, config.Params)
	if err != nil {
		log.Error(service.ServerIdentity(), "Could not initialise protocol", err)
		return nil, err
	}

	return p, nil
}

// Close Session

func (service *Service) newProtoCloseSession(tn *onet.TreeNodeInstance, cfg *onet.GenericConfig) (onet.ProtocolInstance, error) {
	log.Lvl2(service.ServerIdentity(), "CloseSession protocol factory")

	// First, extract configuration
	config := &messages.CloseSessionConfig{}
	err := config.UnmarshalBinary(cfg.Data)
	if err != nil {
		log.Error(service.ServerIdentity(), "Could not extract protocol configuration:", err)
		return nil, err
	}

	// Then, create the protocol with the known parameters and the one just received
	p, err := serviceProto.NewCloseSessionProtocol(tn, service.sessions, config.SessionID)
	if err != nil {
		log.Error(service.ServerIdentity(), "Could not initialise protocol", err)
		return nil, err
	}

	return p, nil
}
