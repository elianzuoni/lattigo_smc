package circuit

import (
	"errors"
	"github.com/ldsec/lattigo/dbfv"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"lattigo-smc/protocols"
	"lattigo-smc/service/messages"
	serviceProto "lattigo-smc/service/protocols"
)

const EncToSharesProtocolName = "EncryptionToSharesProtocol"
const SharesToEncProtocolName = "SharesToEncryptionProtocol"
const CreateCircuitProtocolName = "CreateCircuitProtocol"
const CloseCircuitProtocolName = "CloseCircuitProtocol"

// Though we have NewProtocol, onet needs to register the protocol name. So we register dummy protocol factories.
func init() {
	_, _ = onet.GlobalProtocolRegister(EncToSharesProtocolName,
		func(tni *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
			return nil, nil
		})

	_, _ = onet.GlobalProtocolRegister(SharesToEncProtocolName,
		func(tni *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
			return nil, nil
		})

	_, _ = onet.GlobalProtocolRegister(CreateCircuitProtocolName,
		func(tni *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
			return nil, nil
		})

	_, _ = onet.GlobalProtocolRegister(CloseCircuitProtocolName,
		func(tni *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
			return nil, nil
		})
}

// NewProtocol starts a new protocol given by the name in the TreeNodeInstance, and returns it correctly initialised.
// It is able to do the initialisation because it has access to the
// Only gets called at children: root has to manually call it, register the instance, and dispatch it.
func (service *Service) NewProtocol(tni *onet.TreeNodeInstance, conf *onet.GenericConfig) (onet.ProtocolInstance, error) {
	var err error
	var protocol onet.ProtocolInstance = nil

	switch tni.ProtocolName() {
	case CreateCircuitProtocolName:
		protocol, err = service.newProtoCreateCircuit(tni, conf)

	case CloseCircuitProtocolName:
		protocol, err = service.newProtoCloseCircuit(tni, conf)

	case protocols.CollectiveRefreshName:
		protocol, err = service.newProtoRefresh(tni, conf)

	case EncToSharesProtocolName:
		protocol, err = service.newProtoE2S(tni, conf)

	case SharesToEncProtocolName:
		protocol, err = service.newProtoS2E(tni, conf)
	}

	if err != nil {
		return nil, err
	}
	return protocol, nil
}

// Create Circuit

func (service *Service) newProtoCreateCircuit(tn *onet.TreeNodeInstance, cfg *onet.GenericConfig) (onet.ProtocolInstance, error) {
	log.Lvl2(service.ServerIdentity(), "CreateCircuit protocol factory")

	// First, extract configuration
	config := &messages.CreateCircuitConfig{}
	err := config.UnmarshalBinary(cfg.Data)
	if err != nil {
		log.Error(service.ServerIdentity(), "Could not extract protocol configuration:", err)
		return nil, err
	}

	// Then, create the protocol with the known parameters and the one just received
	p, err := serviceProto.NewCreateCircuitProtocol(tn, service.circuits, config.SessionID, config.CircuitID, config.Description)
	if err != nil {
		log.Error(service.ServerIdentity(), "Could not initialise protocol", err)
		return nil, err
	}

	return p, nil
}

// Close Session

func (service *Service) newProtoCloseCircuit(tn *onet.TreeNodeInstance, cfg *onet.GenericConfig) (onet.ProtocolInstance, error) {
	log.Lvl2(service.ServerIdentity(), "CloseCircuit protocol factory")

	// First, extract configuration
	config := &messages.CloseCircuitConfig{}
	err := config.UnmarshalBinary(cfg.Data)
	if err != nil {
		log.Error(service.ServerIdentity(), "Could not extract protocol configuration:", err)
		return nil, err
	}

	// Then, create the protocol with the known parameters and the one just received
	p, err := serviceProto.NewCloseCircuitProtocol(tn, service.circuits, config.CircuitID)
	if err != nil {
		log.Error(service.ServerIdentity(), "Could not initialise protocol", err)
		return nil, err
	}

	return p, nil
}

// Refresh

func (service *Service) newProtoRefresh(tn *onet.TreeNodeInstance, cfg *onet.GenericConfig) (onet.ProtocolInstance, error) {
	log.Lvl2(service.ServerIdentity(), "Refresh protocol factory")

	// First, extract configuration
	config := &messages.RefreshConfig{}
	err := config.UnmarshalBinary(cfg.Data)
	if err != nil {
		log.Error(service.ServerIdentity(), "Could not extract protocol configuration:", err)
		return nil, err
	}

	// Then, extract session, if exists
	s, ok := service.GetSessionService().GetSession(config.SessionID)
	if !ok {
		err = errors.New("Requested session does not exist")
		log.Error(service.ServerIdentity(), err)
		return nil, err
	}

	// Instantiate protocol with incomplete constructor
	log.Lvl2(service.ServerIdentity(), "Instantiating protocol with incomplete constructor")
	protocol, err := protocols.NewCollectiveRefresh(tn)
	if err != nil {
		log.Error(service.ServerIdentity(), "Could not instantiate protocol")
		return nil, err
	}
	refresh := protocol.(*protocols.RefreshProtocol)

	// Finally, initialise the rest of the fields
	log.Lvl3(service.ServerIdentity(), "Initialising protocol")
	crpGen := dbfv.NewCRPGenerator(s.Params, config.Seed)
	crs := crpGen.ClockNew()
	err = refresh.Init(*s.Params, s.GetSecretKeyShare(), *config.Ciphertext, *crs)
	if err != nil {
		log.Error(service.ServerIdentity(), "Could not initialise protocol", err)
		return nil, err
	}

	return refresh, nil
}

// Encryption to shares

func (service *Service) newProtoE2S(tn *onet.TreeNodeInstance, cfg *onet.GenericConfig) (onet.ProtocolInstance, error) {
	log.Lvl2(service.ServerIdentity(), "EncToShares protocol factory")

	// First, extract configuration
	config := &messages.E2SConfig{}
	err := config.UnmarshalBinary(cfg.Data)
	if err != nil {
		log.Error(service.ServerIdentity(), "Could not extract protocol configuration:", err)
		return nil, err
	}

	// Then, extract session, if exists
	s, ok := service.GetSessionService().GetSession(config.SessionID)
	if !ok {
		err = errors.New("Requested session does not exist")
		log.Error(service.ServerIdentity(), err)
		return nil, err
	}

	// Then, create the protocol with the known parameters and the ones received in config
	log.Lvl3(service.ServerIdentity(), "Creating protocol")
	sigmaSmudging := s.Params.Sigma // TODO: how to set?
	e2sp, err := protocols.NewEncryptionToSharesProtocol(tn, s.Params, sigmaSmudging, s.GetSecretKeyShare(),
		config.Ciphertext, s.NewShareFinaliser(config.SharesID))
	if err != nil {
		log.Error(service.ServerIdentity(), "Could not initialise protocol", err)
		return nil, err
	}

	return e2sp, nil
}

// Shares to encryption

func (service *Service) newProtoS2E(tn *onet.TreeNodeInstance, cfg *onet.GenericConfig) (onet.ProtocolInstance, error) {
	log.Lvl2(service.ServerIdentity(), "SharesToEnc protocol factory")

	// First, extract configuration
	config := &messages.S2EConfig{}
	err := config.UnmarshalBinary(cfg.Data)
	if err != nil {
		log.Error(service.ServerIdentity(), "Could not extract protocol configuration:", err)
		return nil, err
	}

	// Then, extract session, if exists
	s, ok := service.GetSessionService().GetSession(config.SessionID)
	if !ok {
		err = errors.New("Requested session does not exist")
		log.Error(service.ServerIdentity(), err)
		return nil, err
	}

	// Then, create the protocol with the known parameters and the one just received
	log.Lvl3(service.ServerIdentity(), "Creating protocol")
	sigmaSmudging := s.Params.Sigma // TODO: how to set?
	cipherCRPgen := dbfv.NewCipherCRPGenerator(s.Params, config.Seed)
	crp := cipherCRPgen.ClockNew()
	// Check if share exists
	share, ok := s.GetAdditiveShare(config.SharesID)
	if !ok {
		err := errors.New(tn.ServerIdentity().Description + "AdditiveShare for ciphertext " +
			config.SharesID.String() + " not available")
		log.Error(err)
		return nil, err
	}
	// Actually construct the protocol
	s2ep, err := protocols.NewSharesToEncryptionProtocol(tn, s.Params, sigmaSmudging, share, s.GetSecretKeyShare(), crp)
	if err != nil {
		log.Error(service.ServerIdentity(), "Could not initialise protocol", err)
		return nil, err
	}

	return s2ep, nil
}
