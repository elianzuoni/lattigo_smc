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
const CloseSessionProtocolName = "CloseSessionProtocolName"

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
func (serv *Service) NewProtocol(tni *onet.TreeNodeInstance, conf *onet.GenericConfig) (onet.ProtocolInstance, error) {
	err := tni.SetConfig(conf) // Needed in order for conf to be sent by onet along the protocol name at the beginning
	if err != nil {
		return nil, err
	}

	var protocol onet.ProtocolInstance = nil

	switch tni.ProtocolName() {
	case protocols.CollectiveKeyGenerationProtocolName:
		protocol, err = serv.newProtoCKG(tni, conf)

	case protocols.RelinearizationKeyProtocolName:
		protocol, err = serv.newProtoEKG(tni, conf)

	case protocols.RotationProtocolName:
		protocol, err = serv.newProtoRKG(tni, conf)

	case CreateSessionProtocolName:
		protocol, err = serv.newProtoCreateSession(tni, conf)

	case CloseSessionProtocolName:
		protocol, err = serv.newProtoCloseSession(tni, conf)
	}

	if err != nil {
		return nil, err
	}
	return protocol, nil
}

// Public key generation

func (serv *Service) newProtoCKG(tn *onet.TreeNodeInstance, cfg *onet.GenericConfig) (onet.ProtocolInstance, error) {
	log.Lvl2(serv.ServerIdentity(), "CKG protocol factory")

	// First, extract configuration
	config := &messages.GenPubKeyConfig{}
	err := config.UnmarshalBinary(cfg.Data)
	if err != nil {
		log.Error(serv.ServerIdentity(), "Could not extract protocol configuration:", err)
		return nil, err
	}

	// Then, extract session, if exists
	s, ok := serv.sessions.GetSession(config.SessionID)
	if !ok {
		err = errors.New("Requested session does not exist")
		log.Error(serv.ServerIdentity(), err)
		return nil, err
	}

	// Instantiate protocol with incomplete constructor
	log.Lvl2(serv.ServerIdentity(), "Instantiating protocol with incomplete constructor")
	protocol, err := protocols.NewCollectiveKeyGeneration(tn)
	if err != nil {
		log.Error(serv.ServerIdentity(), "Could not instantiate protocol")
		return nil, err
	}
	ckgp := protocol.(*protocols.CollectiveKeyGenerationProtocol)

	// Generate the CRP
	crpGen := dbfv.NewCRPGenerator(s.Params, config.Seed)
	crp := crpGen.ClockNew()

	// Finally, initialise the rest of the fields
	log.Lvl3(serv.ServerIdentity(), "Initialising protocol")
	err = ckgp.Init(s.Params, s.SkShard, crp)
	if err != nil {
		log.Error(serv.ServerIdentity(), "Could not initialise protocol")
		return nil, err
	}

	return ckgp, err
}

// Evaluation key generation

func (serv *Service) newProtoEKG(tn *onet.TreeNodeInstance, cfg *onet.GenericConfig) (onet.ProtocolInstance, error) {
	log.Lvl2(serv.ServerIdentity(), "EKG protocol factory")

	// First, extract configuration
	config := &messages.GenEvalKeyConfig{}
	err := config.UnmarshalBinary(cfg.Data)
	if err != nil {
		log.Error(serv.ServerIdentity(), "Could not extract protocol configuration:", err)
		return nil, err
	}

	// Then, extract session, if exists
	s, ok := serv.sessions.GetSession(config.SessionID)
	if !ok {
		err = errors.New("Requested session does not exist")
		log.Error(serv.ServerIdentity(), err)
		return nil, err
	}

	// Instantiate protocol with incomplete constructor
	log.Lvl2(serv.ServerIdentity(), "Instantiating protocol with incomplete constructor")
	protocol, err := protocols.NewRelinearizationKey(tn)
	if err != nil {
		log.Error(serv.ServerIdentity(), "Could not instantiate protocol")
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
	log.Lvl3(serv.ServerIdentity(), "Initialising protocol")
	err = ekgp.Init(*s.Params, *s.SkShard, crp)
	if err != nil {
		log.Error(serv.ServerIdentity(), "Could not initialise protocol", err)
		return nil, err
	}

	return ekgp, nil
}

// Rotation key generation

func (serv *Service) newProtoRKG(tn *onet.TreeNodeInstance, cfg *onet.GenericConfig) (onet.ProtocolInstance, error) {
	log.Lvl2(serv.ServerIdentity(), "RKG protocol factory")

	// First, extract configuration
	config := &messages.GenRotKeyConfig{}
	err := config.UnmarshalBinary(cfg.Data)
	if err != nil {
		log.Error(serv.ServerIdentity(), "Could not extract protocol configuration:", err)
		return nil, err
	}

	// Then, extract session, if exists
	s, ok := serv.sessions.GetSession(config.SessionID)
	if !ok {
		err = errors.New("Requested session does not exist")
		log.Error(serv.ServerIdentity(), err)
		return nil, err
	}

	// Instantiate protocol with incomplete constructor
	log.Lvl2(serv.ServerIdentity(), "Instantiating protocol with incomplete constructor")
	protocol, err := protocols.NewRotationKey(tn)
	if err != nil {
		log.Error(serv.ServerIdentity(), "Could not instantiate protocol")
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
	log.Lvl3(serv.ServerIdentity(), "Initialising protocol")
	// No need to lock rotation key here. The root (which is the only one that uses it) has already locked it.
	// TODO IMPORTANT: modify this when decentralising rotation key
	err = rkgp.Init(s.Params, *s.SkShard, s.RotationKey, bfv.Rotation(config.RotIdx), config.K, crp)
	if err != nil {
		log.Error(serv.ServerIdentity(), "Could not initialise protocol", err)
		return nil, err
	}

	return rkgp, nil
}

// Create Session

func (serv *Service) newProtoCreateSession(tn *onet.TreeNodeInstance, cfg *onet.GenericConfig) (onet.ProtocolInstance, error) {
	log.Lvl2(serv.ServerIdentity(), "CreateSession protocol factory")

	// First, extract configuration
	config := &messages.CreateSessionConfig{}
	err := config.UnmarshalBinary(cfg.Data)
	if err != nil {
		log.Error(serv.ServerIdentity(), "Could not extract protocol configuration:", err)
		return nil, err
	}

	// Then, create the protocol with the known parameters and the one just received
	p, err := serviceProto.NewCreateSessionProtocol(tn, serv.sessions, config.SessionID, config.Roster, config.Params)
	if err != nil {
		log.Error(serv.ServerIdentity(), "Could not initialise protocol", err)
		return nil, err
	}

	return p, nil
}

// Close Session

func (serv *Service) newProtoCloseSession(tn *onet.TreeNodeInstance, cfg *onet.GenericConfig) (onet.ProtocolInstance, error) {
	log.Lvl2(serv.ServerIdentity(), "CloseSession protocol factory")

	// First, extract configuration
	config := &messages.CloseSessionConfig{}
	err := config.UnmarshalBinary(cfg.Data)
	if err != nil {
		log.Error(serv.ServerIdentity(), "Could not extract protocol configuration:", err)
		return nil, err
	}

	// Then, create the protocol with the known parameters and the one just received
	p, err := serviceProto.NewCloseSessionProtocol(tn, serv.sessions, config.SessionID)
	if err != nil {
		log.Error(serv.ServerIdentity(), "Could not initialise protocol", err)
		return nil, err
	}

	return p, nil
}
