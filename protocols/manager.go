package protocols

import (
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"protocols/utils"
)

func init() {
	onet.GlobalProtocolRegister("FVCollectiveKeyGeneration", NewCollectiveKeyGeneration)
}



func (ckgp *CollectiveKeyGenerationProtocol) Start() error {
	log.Lvl1(ckgp.ServerIdentity(), "Started Collective Public Key Generation protocol")

	ckgp.ChannelParams <- StructParameters{ckgp.TreeNode(), Parameters{ckgp.Params}}
	return nil
}



func (ckgp *CollectiveKeyGenerationProtocol) Dispatch() error {

	ckg_0, e := ckgp.CollectiveKeyGeneration()
	if e != nil {
		return e
	}

	log.Lvl1(ckgp.ServerIdentity(), "Completed Collective Public Key Generation protocol ")
	//utils.PrintNewKeyPair()
	log.Lvl1(ckgp.ServerIdentity(), " Got key :", ckg_0)
	//
	//Afterwards need to do RLK, CKS, PCKS and then we are ready to run




	return nil
}


func (ckgp *CollectiveKeyGenerationProtocol) Shutdown() error{
	log.Lvl1(ckgp.ServerIdentity(), ": shutting down.")
	ckgp.TreeNodeInstance.Shutdown()
	return nil
}





/** *****************Utility FOR KEY SWITCHING******************* **/



func (cks *CollectiveKeySwitchingProtocol) Start() error{
	log.Lvl1(cks.ServerIdentity(), "Starting collective key switching for key : " , cks.Params)
	//TODO why hhere have to write all ??
	cks.ChannelParams <- StructSwitchParameters{cks.TreeNode(),SwitchingParameters{cks.Params.Params,cks.Params.SkInput,cks.Params.SkOutput,cks.Params.cipher}}

	return nil

}


func (cks *CollectiveKeySwitchingProtocol) Dispatch() error{

	//start the key switching
	res, err := cks.CollectiveKeySwitching()
	utils.Check(err)

	log.Lvl1("Resulting key : " , res)

	return nil

}

func (cks *CollectiveKeySwitchingProtocol) Shutdown() error{
	cks.TreeNodeInstance.Shutdown()
	return nil


}




