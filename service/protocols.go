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

	case protocols.CollectiveKeySwitchingProtocolName:
		protocol, err = s.newProtoCKS(tn)

	case protocols.CollectivePublicKeySwitchingProtocolName:
		protocol, err = s.newProtoCPKS(tn)

	case protocols.RelinearizationKeyProtocolName:
		protocol, err = s.newProtoRLK(tn)

	case protocols.RotationProtocolName:
		protocol, err = s.newProtoRotKG(tn)
	case protocols.CollectiveRefreshName:
		protocol, err = s.newProtoRefresh(tn)

	}
	if err != nil {
		return nil, err
	}
	return protocol, nil
}

func (s *Service) newProtoCKG(tn *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
	log.Lvl1(s.ServerIdentity(), ": New protocol ckgp")
	protocol, err := protocols.NewCollectiveKeyGeneration(tn)
	if err != nil {
		return nil, err
	}
	ckgp := protocol.(*protocols.CollectiveKeyGenerationProtocol)
	//init
	crp := s.crpGen.ClockNew()
	err = ckgp.Init(s.Params, s.SecretKey, crp)
	if !tn.IsRoot() {
		go func() {

			log.Lvl1(s.ServerIdentity(), "Waiting for the protocol to be finished...(NewProtocol)")
			ckgp.Wait()
			log.Lvl1(tn.ServerIdentity(), " : done with collective key gen ! ")

			s.SecretKey = ckgp.Sk
			s.DecryptorSk = bfv.NewDecryptor(s.Params, s.SecretKey)
			s.Encoder = bfv.NewEncoder(s.Params)
			s.PublicKey = bfv.NewKeyGenerator(s.Params).GenPublicKey(s.SecretKey)
			s.pubKeyGenerated = true
		}()

	}
	return protocol, err
}

func (s *Service) newProtoCKS(tn *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
	return nil, nil
}

func (s *Service) newProtoCPKS(tn *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
	log.Lvl1(s.ServerIdentity(), ": New protocol cpksp")
	protocol, err := protocols.NewCollectivePublicKeySwitching(tn)
	if err != nil {
		return nil, err
	}
	pcks := protocol.(*protocols.CollectivePublicKeySwitchingProtocol)
	var publickey bfv.PublicKey
	var ciphertext *bfv.Ciphertext
	sp := <-s.SwitchingParameters
	publickey = sp.PublicKey
	ciphertext = &sp.Ciphertext
	err = pcks.Init(*s.Params, publickey, *s.SecretKey, ciphertext)
	if err != nil {
		return nil, err
	}
	return protocol, err
}

func (s *Service) newProtoRLK(tn *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
	log.Lvl1(s.ServerIdentity(), ": New protocol rlkp")
	protocol, err := protocols.NewRelinearizationKey(tn)
	if err != nil {
		return nil, err
	}
	rkp := (protocol).(*protocols.RelinearizationKeyProtocol)
	modulus := s.Params.Moduli.Qi
	crp := make([]*ring.Poly, len(modulus))
	for j := 0; j < len(modulus); j++ {
		crp[j] = s.crpGen.ClockNew()
	}
	err = rkp.Init(*s.Params, *s.SecretKey, crp)
	if err != nil {
		log.Error("Error while generating Relin key : ", err)
	}
	if !tn.IsRoot() {
		go func() {

			log.Lvl1(s.ServerIdentity(), "Waiting for the protocol to be finished...(Relin Protocol)")
			rkp.Wait()
			log.Lvl1(tn.ServerIdentity(), " : done with collective relinkey gen ! ")

			s.evalKeyGenerated = true
		}()

	}
	return protocol, nil
}

func (s *Service) newProtoRotKG(tn *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
	protocol, err := protocols.NewRotationKey(tn)
	if err != nil {
		log.Error("Could not start rotation :", err)
		return nil, err

	}
	rotkey := (protocol).(*protocols.RotationKeyProtocol)
	modulus := s.Params.Moduli.Qi
	crp := make([]*ring.Poly, len(modulus))
	for j := 0; j < len(modulus); j++ {
		crp[j] = s.crpGen.ClockNew()
	}
	var rotIdx = s.RotIdx
	var K = s.K
	if s.RotationKey != nil {
		err = rotkey.Init(s.Params, *s.SecretKey, bfv.Rotation(rotIdx), K, crp, false, s.RotationKey)
	} else {
		err = rotkey.Init(s.Params, *s.SecretKey, bfv.Rotation(rotIdx), K, crp, true, nil)
	}
	if err != nil {
		log.Error("Could not start rotation : ", err)
		return nil, err

	}
	if !tn.IsRoot() {
		go func() {
			rotkey.Wait()
			s.rotKeyGenerated = true
		}()
	}
	return protocol, err
}

func (s *Service) newProtoRefresh(tn *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
	log.Lvl1(s.ServerIdentity(), "New Refresh protocol started ")
	protocol, err := protocols.NewCollectiveRefresh(tn)
	if err != nil {
		return nil, err
	}
	//Setup the parameters
	refresh := (protocol).(*protocols.RefreshProtocol)
	var ciphertext *bfv.Ciphertext
	var crs *ring.Poly
	ciphertext = <-s.RefreshParams
	crs = s.crpGen.ClockNew()
	err = refresh.Init(*s.Params, s.SecretKey, *ciphertext, *crs)
	return protocol, nil
}
