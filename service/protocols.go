package service

import (
	"errors"
	"github.com/ldsec/lattigo/bfv"
	"github.com/ldsec/lattigo/dbfv"
	"github.com/ldsec/lattigo/ring"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"lattigo-smc/protocols"
)

// Though we have NewProtocol, onet needs to register the protocol name
func init() {
	_, _ = onet.GlobalProtocolRegister(EncToSharesProtocolName,
		func(tni *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
			return nil, nil
		})

	_, _ = onet.GlobalProtocolRegister(SharesToEncProtocolName,
		func(tni *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
			return nil, nil
		})
}

// NewProtocol starts a new protocol given by the name in the TreeNodeInstance, and returns it correctly initialised.
// It is able to do the initialisation because it has access to the service.
// Only gets called at children: root has to manually call it, register the instance, and dispatch it.
func (smc *Service) NewProtocol(tni *onet.TreeNodeInstance, conf *onet.GenericConfig) (onet.ProtocolInstance, error) {
	err := tni.SetConfig(conf) // Needed in order for conf to be sent by onet along the protocol name at the beginning
	if err != nil {
		return nil, err
	}

	var protocol onet.ProtocolInstance = nil

	switch tni.ProtocolName() {
	case protocols.CollectiveKeyGenerationProtocolName:
		protocol, err = smc.newProtoCKG(tni, conf)

	case protocols.RelinearizationKeyProtocolName:
		protocol, err = smc.newProtoEKG(tni, conf)

	case protocols.RotationProtocolName:
		protocol, err = smc.newProtoRKG(tni, conf)

	case protocols.CollectivePublicKeySwitchingProtocolName:
		protocol, err = smc.newProtoPCKS(tni, conf)

	case protocols.CollectiveRefreshName:
		protocol, err = smc.newProtoRefresh(tni, conf)

	case EncToSharesProtocolName:
		protocol, err = smc.newProtoE2S(tni, conf)

	case SharesToEncProtocolName:
		protocol, err = smc.newProtoS2E(tni, conf)
	}

	if err != nil {
		return nil, err
	}
	return protocol, nil
}

// Collective key generation

func (smc *Service) newProtoCKG(tn *onet.TreeNodeInstance, cfg *onet.GenericConfig) (onet.ProtocolInstance, error) {
	log.Lvl2(smc.ServerIdentity(), "CKG protocol factory")

	// First, extract configuration
	config := &GenPubKeyConfig{}
	err := config.UnmarshalBinary(cfg.Data)
	if err != nil {
		log.Error(smc.ServerIdentity(), "Could not extract protocol configuration:", err)
		return nil, err
	}

	// Then, extract session, if exists
	smc.sessionsLock.RLock()
	s, ok := smc.sessions[config.SessionID]
	smc.sessionsLock.RUnlock()
	if !ok {
		err = errors.New("Requested session does not exist")
		log.Error(smc.ServerIdentity(), err)
		return nil, err
	}

	// Instantiate protocol with incomplete constructor
	log.Lvl2(smc.ServerIdentity(), "Instantiating protocol with incomplete constructor")
	protocol, err := protocols.NewCollectiveKeyGeneration(tn)
	if err != nil {
		log.Error(smc.ServerIdentity(), "Could not instantiate protocol")
		return nil, err
	}
	ckgp := protocol.(*protocols.CollectiveKeyGenerationProtocol)

	// Generate the CRP
	crpGen := dbfv.NewCRPGenerator(s.Params, config.Seed)
	crp := crpGen.ClockNew()

	// Finally, initialise the rest of the fields
	log.Lvl3(smc.ServerIdentity(), "Initialising protocol")
	err = ckgp.Init(s.Params, s.skShard, crp)
	if err != nil {
		log.Error(smc.ServerIdentity(), "Could not initialise protocol")
		return nil, err
	}

	return ckgp, err
}

// Evaluation key generation

func (smc *Service) newProtoEKG(tn *onet.TreeNodeInstance, cfg *onet.GenericConfig) (onet.ProtocolInstance, error) {
	log.Lvl2(smc.ServerIdentity(), "EKG protocol factory")

	// First, extract configuration
	config := &GenEvalKeyConfig{}
	err := config.UnmarshalBinary(cfg.Data)
	if err != nil {
		log.Error(smc.ServerIdentity(), "Could not extract protocol configuration:", err)
		return nil, err
	}

	// Then, extract session, if exists
	smc.sessionsLock.RLock()
	s, ok := smc.sessions[config.SessionID]
	smc.sessionsLock.RUnlock()
	if !ok {
		err = errors.New("Requested session does not exist")
		log.Error(smc.ServerIdentity(), err)
		return nil, err
	}

	// Instantiate protocol with incomplete constructor
	log.Lvl2(smc.ServerIdentity(), "Instantiating protocol with incomplete constructor")
	protocol, err := protocols.NewRelinearizationKey(tn)
	if err != nil {
		log.Error(smc.ServerIdentity(), "Could not instantiate protocol")
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
	log.Lvl3(smc.ServerIdentity(), "Initialising protocol")
	err = ekgp.Init(*s.Params, *s.skShard, crp)
	if err != nil {
		log.Error(smc.ServerIdentity(), "Could not initialise protocol", err)
		return nil, err
	}

	return ekgp, nil
}

// Rotation key generation

func (smc *Service) newProtoRKG(tn *onet.TreeNodeInstance, cfg *onet.GenericConfig) (onet.ProtocolInstance, error) {
	log.Lvl2(smc.ServerIdentity(), "RKG protocol factory")

	// First, extract configuration
	config := &GenRotKeyConfig{}
	err := config.UnmarshalBinary(cfg.Data)
	if err != nil {
		log.Error(smc.ServerIdentity(), "Could not extract protocol configuration:", err)
		return nil, err
	}

	// Then, extract session, if exists
	smc.sessionsLock.RLock()
	s, ok := smc.sessions[config.SessionID]
	smc.sessionsLock.RUnlock()
	if !ok {
		err = errors.New("Requested session does not exist")
		log.Error(smc.ServerIdentity(), err)
		return nil, err
	}

	// Instantiate protocol with incomplete constructor
	log.Lvl2(smc.ServerIdentity(), "Instantiating protocol with incomplete constructor")
	protocol, err := protocols.NewRotationKey(tn)
	if err != nil {
		log.Error(smc.ServerIdentity(), "Could not instantiate protocol")
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
	log.Lvl3(smc.ServerIdentity(), "Initialising protocol")
	// No need to lock rotation key here. The root (which is the only one that uses it) has already locked it.
	// TODO IMPORTANT: modify this when decentralising rotation key
	err = rkgp.Init(s.Params, *s.skShard, s.rotationKey, bfv.Rotation(config.RotIdx), config.K, crp)
	if err != nil {
		log.Error(smc.ServerIdentity(), "Could not initialise protocol", err)
		return nil, err
	}

	return rkgp, nil
}

// Public collective key switching

func (smc *Service) newProtoPCKS(tn *onet.TreeNodeInstance, cfg *onet.GenericConfig) (onet.ProtocolInstance, error) {
	log.Lvl2(smc.ServerIdentity(), "PCKS protocol factory")

	// First, extract configuration
	config := &PublicSwitchConfig{}
	err := config.UnmarshalBinary(cfg.Data)
	if err != nil {
		log.Error(smc.ServerIdentity(), "Could not extract protocol configuration:", err)
		return nil, err
	}

	// Then, extract session, if exists
	smc.sessionsLock.RLock()
	s, ok := smc.sessions[config.SessionID]
	smc.sessionsLock.RUnlock()
	if !ok {
		err = errors.New("Requested session does not exist")
		log.Error(smc.ServerIdentity(), err)
		return nil, err
	}

	// Instantiate protocol with incomplete constructor
	log.Lvl2(smc.ServerIdentity(), "Instantiating protocol with incomplete constructor")
	protocol, err := protocols.NewCollectivePublicKeySwitching(tn)
	if err != nil {
		log.Error(smc.ServerIdentity(), "Could not instantiate protocol")
		return nil, err
	}
	pcks := protocol.(*protocols.CollectivePublicKeySwitchingProtocol)

	// Finally, initialise the rest of the fields
	log.Lvl3(smc.ServerIdentity(), "Initialising protocol")
	err = pcks.Init(*s.Params, *config.PublicKey, *s.skShard, config.Ciphertext)
	if err != nil {
		log.Error(smc.ServerIdentity(), "Could not initialise protocol", err)
		return nil, err
	}

	return pcks, err
}

// Refresh

func (smc *Service) newProtoRefresh(tn *onet.TreeNodeInstance, cfg *onet.GenericConfig) (onet.ProtocolInstance, error) {
	log.Lvl2(smc.ServerIdentity(), "Refresh protocol factory")

	// First, extract configuration
	config := &RefreshConfig{}
	err := config.UnmarshalBinary(cfg.Data)
	if err != nil {
		log.Error(smc.ServerIdentity(), "Could not extract protocol configuration:", err)
		return nil, err
	}

	// Then, extract session, if exists
	smc.sessionsLock.RLock()
	s, ok := smc.sessions[config.SessionID]
	smc.sessionsLock.RUnlock()
	if !ok {
		err = errors.New("Requested session does not exist")
		log.Error(smc.ServerIdentity(), err)
		return nil, err
	}

	// Instantiate protocol with incomplete constructor
	log.Lvl2(smc.ServerIdentity(), "Instantiating protocol with incomplete constructor")
	protocol, err := protocols.NewCollectiveRefresh(tn)
	if err != nil {
		log.Error(smc.ServerIdentity(), "Could not instantiate protocol")
		return nil, err
	}
	refresh := protocol.(*protocols.RefreshProtocol)

	// Finally, initialise the rest of the fields
	log.Lvl3(smc.ServerIdentity(), "Initialising protocol")
	crpGen := dbfv.NewCRPGenerator(s.Params, config.Seed)
	crs := crpGen.ClockNew()
	err = refresh.Init(*s.Params, s.skShard, *config.Ciphertext, *crs)
	if err != nil {
		log.Error(smc.ServerIdentity(), "Could not initialise protocol", err)
		return nil, err
	}

	return refresh, nil
}

// Encryption to shares

const EncToSharesProtocolName = "EncryptionToSharesProtocol"

func (smc *Service) newProtoE2S(tn *onet.TreeNodeInstance, cfg *onet.GenericConfig) (onet.ProtocolInstance, error) {
	log.Lvl2(smc.ServerIdentity(), "EncToShares protocol factory")

	// First, extract configuration
	config := &E2SConfig{}
	err := config.UnmarshalBinary(cfg.Data)
	if err != nil {
		log.Error(smc.ServerIdentity(), "Could not extract protocol configuration:", err)
		return nil, err
	}

	// Then, extract session, if exists
	smc.sessionsLock.RLock()
	s, ok := smc.sessions[config.SessionID]
	smc.sessionsLock.RUnlock()
	if !ok {
		err = errors.New("Requested session does not exist")
		log.Error(smc.ServerIdentity(), err)
		return nil, err
	}

	// Then, create the protocol with the known parameters and the ones received in config
	log.Lvl3(smc.ServerIdentity(), "Creating protocol")
	sigmaSmudging := s.Params.Sigma // TODO: how to set?
	e2sp, err := protocols.NewEncryptionToSharesProtocol(tn, s.Params, sigmaSmudging, s.skShard, config.Ciphertext,
		s.newShareFinaliser(config.SharesID))
	if err != nil {
		log.Error(smc.ServerIdentity(), "Could not initialise protocol", err)
		return nil, err
	}

	return e2sp, nil
}

// This method returns a finaliser (as required by the EncryptionToSharesProtocol constructor)
// that saves the share under the provided CipherID in the Service's shares database.
func (s *Session) newShareFinaliser(sharesID SharesID) func(share *dbfv.AdditiveShare) {
	return func(share *dbfv.AdditiveShare) {
		s.sharesLock.Lock()
		s.shares[sharesID] = share
		s.sharesLock.Unlock()
	}
}

// Shares to encryption

const SharesToEncProtocolName = "SharesToEncryptionProtocol"

func (smc *Service) newProtoS2E(tn *onet.TreeNodeInstance, cfg *onet.GenericConfig) (onet.ProtocolInstance, error) {
	log.Lvl2(smc.ServerIdentity(), "SharesToEnc protocol factory")

	// First, extract configuration
	config := &S2EConfig{}
	err := config.UnmarshalBinary(cfg.Data)
	if err != nil {
		log.Error(smc.ServerIdentity(), "Could not extract protocol configuration:", err)
		return nil, err
	}

	// Then, extract session, if exists
	smc.sessionsLock.RLock()
	s, ok := smc.sessions[config.SessionID]
	smc.sessionsLock.RUnlock()
	if !ok {
		err = errors.New("Requested session does not exist")
		log.Error(smc.ServerIdentity(), err)
		return nil, err
	}

	// Then, create the protocol with the known parameters and the one just received
	log.Lvl3(smc.ServerIdentity(), "Creating protocol")
	sigmaSmudging := s.Params.Sigma // TODO: how to set?
	cipherCRPgen := dbfv.NewCipherCRPGenerator(s.Params, config.Seed)
	crp := cipherCRPgen.ClockNew()
	// Check if share exists
	s.sharesLock.RLock()
	share, ok := s.shares[config.SharesID]
	s.sharesLock.RUnlock()
	if !ok {
		err := errors.New(tn.ServerIdentity().Description + "AdditiveShare for ciphertext " +
			config.SharesID.String() + " not available")
		log.Error(err)
		return nil, err
	}
	// Actually construct the protocol
	s2ep, err := protocols.NewSharesToEncryptionProtocol(tn, s.Params, sigmaSmudging, share, s.skShard, crp)
	if err != nil {
		log.Error(smc.ServerIdentity(), "Could not initialise protocol", err)
		return nil, err
	}

	return s2ep, nil
}
