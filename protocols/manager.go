package protocols

import (
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"protocols/utils"
	"time"
)

func init() {
	onet.GlobalProtocolRegister("CollectiveKeyGeneration", NewCollectiveKeyGeneration)
	onet.GlobalProtocolRegister("CollectiveKeySwitching",NewCollectiveKeySwitching)
}



func (ckgp *CollectiveKeyGenerationProtocol) Start() error {
	log.Lvl1(ckgp.ServerIdentity(), "Started Collective Public Key Generation protocol")

	ckgp.ChannelParams <- StructParameters{ckgp.TreeNode(), ckgp.Params}
	return nil
}



func (ckgp *CollectiveKeyGenerationProtocol) Dispatch() error {

	ckg_0, e := ckgp.CollectiveKeyGeneration()
	if e != nil {
		return e
	}

	//log.Lvl1(ckgp.ServerIdentity(), "Completed Collective Public Key Generation protocol ")
	xs := ckg_0.Get()
	log.Lvl4(ckgp.ServerIdentity(), " Got key :", xs[0] ," \n. " , xs[1])




	//TODO turn off in real scenario..
	//for the test - send all to root and in the test check that all keys are equals.

	var test = true
	if test {
		//if ! ckgp.IsRoot(){
			err := ckgp.SendTo(ckgp.Root(),ckg_0.Get()[0])

			if err != nil{
				log.Lvl1("Error in key sending to root : " , err)
			}
		//}
		//wait to allow test to get the values.
		<- time.After(time.Second*2)

	}
	log.Lvl1(ckgp.ServerIdentity() , " : im done")
	ckgp.Done()


	return nil
}


func (ckgp *CollectiveKeyGenerationProtocol) Shutdown() error{
	//log.Lvl1(ckgp.ServerIdentity(), ": shutting down.")
	ckgp.TreeNodeInstance.Shutdown()
	return nil
}





/** *****************Utility FOR KEY SWITCHING******************* **/



func (cks *CollectiveKeySwitchingProtocol) Start() error{
	log.Lvl1(cks.ServerIdentity(), "Starting collective key switching for key : " , cks.Params)
	//TODO Here only the master node gets access to the ciphertext because its a pointer.
	//find a way to take advantage of the unmarshalin

	cks.ChannelParams <- StructSwitchParameters{cks.TreeNode(),SwitchingParameters{cks.Params.Params,cks.Params.SkInputHash,cks.Params.SkOutputHash,cks.Params.Ciphertext}}

	return nil

}


func (cks *CollectiveKeySwitchingProtocol) Dispatch() error{

	//start the key switching

	res, err := cks.CollectiveKeySwitching()
	utils.Check(err)

	log.Lvl1("Resulting ciphertext : " , *res)


	return nil

}

func (cks *CollectiveKeySwitchingProtocol) Shutdown() error{
	cks.TreeNodeInstance.Shutdown()
	return nil


}




