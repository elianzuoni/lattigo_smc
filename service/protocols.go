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

// NewProtocol starts a new protocol given by the name in the TreeNodeInstance, and returns it correctly initialised.
// It is able to do the initialisation because it has access to the service.
// Only gets called at children: root has to manually call it, register the instance, and dispatch it.
func (s *Service) NewProtocol(tn *onet.TreeNodeInstance, conf *onet.GenericConfig) (onet.ProtocolInstance, error) {
	err := tn.SetConfig(conf)
	if err != nil {
		return nil, err
	}
	var protocol onet.ProtocolInstance = nil

	switch tn.ProtocolName() {
	case protocols.CollectiveKeyGenerationProtocolName:
		protocol, err = s.newProtoCKG(tn)

	case protocols.RelinearizationKeyProtocolName:
		protocol, err = s.newProtoEKG(tn)

	case protocols.RotationProtocolName:
		protocol, err = s.newProtoRKG(tn)

	case protocols.CollectivePublicKeySwitchingProtocolName:
		protocol, err = s.newProtoPCKS(tn)

	case protocols.CollectiveRefreshName:
		protocol, err = s.newProtoRefresh(tn)

	case EncToSharesProtocolName:
		protocol, err = s.newProtoE2S(tn)

	case SharesToEncProtocolName:
		protocol, err = s.newProtoS2E(tn)
	}

	if err != nil {
		return nil, err
	}
	return protocol, nil
}

// Collective key generation

func (s *Service) newProtoCKG(tn *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
	log.Lvl2(s.ServerIdentity(), "CKG protocol factory")

	// First, instantiate protocol with incomplete constructor
	log.Lvl2(s.ServerIdentity(), "Instantiating protocol with incomplete constructor")
	protocol, err := protocols.NewCollectiveKeyGeneration(tn)
	if err != nil {
		log.Error(s.ServerIdentity(), "Could not instantiate protocol")
		return nil, err
	}
	ckgp := protocol.(*protocols.CollectiveKeyGenerationProtocol)

	// Before reading the fields in the Service to initialise the protocol,
	// wait until they are ready (they are set in processSetupBroadcast).
	log.Lvl2(s.ServerIdentity(), "Waiting for fields to be available...")
	s.waitCKG.Lock()

	// Finally, initialise the rest of the fields
	log.Lvl3(s.ServerIdentity(), "Initialising protocol")
	crp := s.crpGen.ClockNew() // TODO: synchronise this use, or have the CRP be decided and propagated by root
	err = ckgp.Init(s.Params, s.skShard, crp)
	if err != nil {
		log.Error(s.ServerIdentity(), "Could not initialise protocol")
		return nil, err
	}

	return ckgp, err
}

// Evaluation key generation

func (s *Service) newProtoEKG(tn *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
	log.Lvl2(s.ServerIdentity(), "EKG protocol factory")

	// First, instantiate protocol with incomplete constructor
	log.Lvl2(s.ServerIdentity(), "Instantiating protocol with incomplete constructor")
	protocol, err := protocols.NewRelinearizationKey(tn)
	if err != nil {
		log.Error(s.ServerIdentity(), "Could not instantiate protocol")
		return nil, err
	}
	ekgp := protocol.(*protocols.RelinearizationKeyProtocol)

	// Before reading the fields in the Service to initialise the protocol,
	// wait until they are ready (they are set in processSetupBroadcast).
	log.Lvl2(s.ServerIdentity(), "Waiting for fields to be available...")
	s.waitEKG.Lock()

	// Finally, initialise the rest of the fields
	log.Lvl3(s.ServerIdentity(), "Initialising protocol")
	modulus := s.Params.Moduli.Qi
	crp := make([]*ring.Poly, len(modulus))
	for j := 0; j < len(modulus); j++ {
		crp[j] = s.crpGen.ClockNew() // TODO: synchronise this use, or have the CRP be decided and propagated by root
	}
	err = ekgp.Init(*s.Params, *s.skShard, crp)
	if err != nil {
		log.Error(s.ServerIdentity(), "Could not initialise protocol", err)
		return nil, err
	}

	return ekgp, nil
}

// Rotation key generation

func (s *Service) newProtoRKG(tn *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
	log.Lvl2(s.ServerIdentity(), "RKG protocol factory")

	// First, instantiate protocol with incomplete constructor
	log.Lvl2(s.ServerIdentity(), "Instantiating protocol with incomplete constructor")
	protocol, err := protocols.NewRotationKey(tn)
	if err != nil {
		log.Error(s.ServerIdentity(), "Could not instantiate protocol")
		return nil, err
	}
	rkgp := protocol.(*protocols.RotationKeyProtocol)

	// Before reading the fields in the Service to initialise the protocol,
	// wait until they are ready (they are set in processSetupBroadcast).
	log.Lvl2(s.ServerIdentity(), "Waiting for fields to be available...")
	s.waitRKG.Lock()

	// Finally, initialise the rest of the fields
	log.Lvl3(s.ServerIdentity(), "Initialising protocol")
	modulus := s.Params.Moduli.Qi
	crp := make([]*ring.Poly, len(modulus))
	for j := 0; j < len(modulus); j++ {
		crp[j] = s.crpGen.ClockNew() // TODO: synchronise this use, or have the CRP be decided and propagated by root
	}
	// TODO: what? What if s.rotationKey == nil?
	if s.rotationKey != nil {
		err = rkgp.Init(s.Params, *s.skShard, bfv.Rotation(s.rotIdx), s.k, crp, false, s.rotationKey)
	} else {
		err = rkgp.Init(s.Params, *s.skShard, bfv.Rotation(s.rotIdx), s.k, crp, true, nil)
	}
	if err != nil {
		log.Error(s.ServerIdentity(), "Could not initialise protocol", err)
		return nil, err
	}

	return rkgp, nil
}

// Public collective key switching

func (s *Service) newProtoPCKS(tn *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
	log.Lvl2(s.ServerIdentity(), "PCKS protocol factory")

	// First, instantiate protocol with incomplete constructor
	log.Lvl2(s.ServerIdentity(), "Instantiating protocol with incomplete constructor")
	protocol, err := protocols.NewCollectivePublicKeySwitching(tn)
	if err != nil {
		log.Error(s.ServerIdentity(), "Could not instantiate protocol")
		return nil, err
	}
	pcks := protocol.(*protocols.CollectivePublicKeySwitchingProtocol)

	// We can directly read the fields, since they come from a channel
	log.Lvl2(s.ServerIdentity(), "Reading switching parameters from channel")
	var pk *bfv.PublicKey
	var ct *bfv.Ciphertext
	sp := <-s.switchingParams
	pk = sp.PublicKey
	ct = sp.Ciphertext

	// Finally, initialise the rest of the fields
	log.Lvl3(s.ServerIdentity(), "Initialising protocol")
	err = pcks.Init(*s.Params, *pk, *s.skShard, ct)
	if err != nil {
		log.Error(s.ServerIdentity(), "Could not initialise protocol", err)
		return nil, err
	}

	return pcks, err
}

// Refresh

func (s *Service) newProtoRefresh(tn *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
	log.Lvl2(s.ServerIdentity(), "Refresh protocol factory")

	// First, instantiate protocol with incomplete constructor
	log.Lvl2(s.ServerIdentity(), "Instantiating protocol with incomplete constructor")
	protocol, err := protocols.NewCollectiveRefresh(tn)
	if err != nil {
		log.Error(s.ServerIdentity(), "Could not instantiate protocol")
		return nil, err
	}
	refresh := protocol.(*protocols.RefreshProtocol)

	// We can directly read the fields, since they come from a channel
	log.Lvl2(s.ServerIdentity(), "Reading refresh parameters from channel")
	ct := <-s.refreshParams

	// Finally, initialise the rest of the fields
	log.Lvl3(s.ServerIdentity(), "Initialising protocol")
	crs := s.crpGen.ClockNew() // TODO: synchronise this use, or have the CRP be decided and propagated by root
	err = refresh.Init(*s.Params, s.skShard, *ct, *crs)
	if err != nil {
		log.Error(s.ServerIdentity(), "Could not initialise protocol", err)
		return nil, err
	}

	return refresh, nil
}

// Encryption to shares

const EncToSharesProtocolName = "EncryptionToSharesProtocol"

func (s *Service) newProtoE2S(tn *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
	log.Lvl2(s.ServerIdentity(), "EncToShares protocol factory")

	// First, read the fields (only the ciphertext) directly, since they come from a channel.
	log.Lvl2(s.ServerIdentity(), "Reading enc-to-shares parameters from channel")
	params := <-s.encToSharesParams

	// Then, create the protocol with the known parameters and the one just received
	log.Lvl3(s.ServerIdentity(), "Creating protocol")
	sigmaSmudging := s.Params.Sigma // TODO: how to set?
	e2sp, err := protocols.NewEncryptionToSharesProtocol(tn, s.Params, sigmaSmudging, s.skShard, params.ct,
		s.newShareFinaliser(params.cipherID))
	if err != nil {
		log.Error(s.ServerIdentity(), "Could not initialise protocol", err)
		return nil, err
	}

	return e2sp, nil
}

// This method returns a finaliser (as required by the EncryptionToSharesProtocol constructor)
// that saves the share under the provided CipherID in the Service's shares database.
func (s *Service) newShareFinaliser(cipherID CipherID) func(share *dbfv.AdditiveShare) {
	return func(share *dbfv.AdditiveShare) {
		s.shares[cipherID] = share
	}
}

// Shares to encryption

const SharesToEncProtocolName = "SharesToEncryptionProtocol"

func (s *Service) newProtoS2E(tn *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
	log.Lvl2(s.ServerIdentity(), "SharesToEnc protocol factory")

	// First, read the fields (only the CipherID) directly, since they come from a channel.
	log.Lvl2(s.ServerIdentity(), "Reading shares-to-enc parameters from channel")
	params := <-s.sharesToEncParams

	// Then, create the protocol with the known parameters and the one just received
	log.Lvl3(s.ServerIdentity(), "Creating protocol")
	sigmaSmudging := s.Params.Sigma  // TODO: how to set?
	crp := s.cipherCRPgen.ClockNew() // TODO: synchronise this use, or have the CRP be decided and propagated by root
	// Check if share exists
	share, ok := s.shares[params.cipherID]
	if !ok {
		err := errors.New(tn.ServerIdentity().Description + "AdditiveShare for ciphertext " +
			params.cipherID.String() + " not available")
		log.Error(err)
		return nil, err
	}
	// Actually construct the protocol
	s2ep, err := protocols.NewSharesToEncryptionProtocol(tn, s.Params, sigmaSmudging, share, s.skShard, crp)
	if err != nil {
		log.Error(s.ServerIdentity(), "Could not initialise protocol", err)
		return nil, err
	}

	return s2ep, nil
}
