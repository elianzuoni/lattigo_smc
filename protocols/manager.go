package protocols

import (
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
)

func init() {
	onet.GlobalProtocolRegister("FVCollectiveKeyGeneration", NewCollectiveKeyGeneration)
}



func (ckgp *CollectiveKeyGenerationProtocol) Start() error {
	log.Lvl1(ckgp.ServerIdentity(), "Started Collective Public Key Generation protocol")

	ckgp.ChannelParams <- StructParameters{nil, Parameters{ckgp.Params}}
	return nil
}



func (ckgp *CollectiveKeyGenerationProtocol) Dispatch() error {

	ckg_0, e := ckgp.CollectiveKeyGeneration()
	if e != nil {
		return e
	}

	log.Lvl1(ckgp.ServerIdentity(), "Completed Collective Public Key Generation protocol ")

	log.Lvl1(ckgp.ServerIdentity(), " Got key :", ckg_0)
	//Afterwards need to do RLK, CKS, PCKS and then we are ready to run
	return nil
}

//
//func (ckgp *CollectiveKeyGenerationProtocol) Shutdown() error{
//	log.Lvl1(ckgp.ServerIdentity(), "Shutting down system.")
//	//maybe free some resources here...
//	//close(ckgp.ChannelParams)
//	//close(ckgp.ChannelPublicKey)
//	//close(ckgp.ChannelPublicKeyShares)
//	return nil
//}
