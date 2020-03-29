package service

import (
	"github.com/ldsec/lattigo/bfv"
	"github.com/ldsec/lattigo/ring"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"lattigo-smc/protocols"
)

//NewProtocol starts a new protocol given by the name in the treenodeinstance and returns it correctly initialized.
func (s *Service) NewProtocol(tn *onet.TreeNodeInstance, conf *onet.GenericConfig) (onet.ProtocolInstance, error) {
	err := tn.SetConfig(conf)
	if err != nil {
		return nil, err
	}
	var protocol onet.ProtocolInstance
	switch tn.ProtocolName() {
	case protocols.CollectiveKeyGenerationProtocolName:
		protocol, err = s.newProtoCKG(tn)

	case protocols.RelinearizationKeyProtocolName:
		protocol, err = s.newProtoEKG(tn)

	case protocols.RotationProtocolName:
		protocol, err = s.newProtoRKG(tn)

	case protocols.CollectiveKeySwitchingProtocolName:
		protocol, err = s.newProtoCKS(tn)

	case protocols.CollectivePublicKeySwitchingProtocolName:
		protocol, err = s.newProtoPCKS(tn)

	case protocols.CollectiveRefreshName:
		protocol, err = s.newProtoRefresh(tn)
	}
	if err != nil {
		return nil, err
	}
	return protocol, nil
}

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
	crp := s.crpGen.ClockNew()
	err = ckgp.Init(s.Params, s.skShard, crp)
	if err != nil {
		log.Error(s.ServerIdentity(), "Could not initialise protocol")
		return nil, err
	}

	return protocol, err
}

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
		crp[j] = s.crpGen.ClockNew()
	}
	err = ekgp.Init(*s.Params, *s.skShard, crp)
	if err != nil {
		log.Error(s.ServerIdentity(), "Could not initialise protocol", err)
		return nil, err
	}

	return protocol, nil
}

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
		crp[j] = s.crpGen.ClockNew()
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

	return protocol, nil
}

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
	sp := <-s.switchingParameters
	pk = sp.PublicKey
	ct = sp.Ciphertext

	// Finally, initialise the rest of the fields
	log.Lvl3(s.ServerIdentity(), "Initialising protocol")
	err = pcks.Init(*s.Params, *pk, *s.skShard, ct)
	if err != nil {
		log.Error(s.ServerIdentity(), "Could not initialise protocol", err)
		return nil, err
	}

	return protocol, err
}

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
	crs := s.crpGen.ClockNew()
	err = refresh.Init(*s.Params, s.skShard, *ct, *crs)
	if err != nil {
		log.Error(s.ServerIdentity(), "Could not initialise protocol", err)
		return nil, err
	}

	return protocol, nil
}

func (s *Service) newProtoCKS(tn *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
	return nil, nil
}
