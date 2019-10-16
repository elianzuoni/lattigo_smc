package protocols

import (
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"time"
)

var test = true

func Test() bool {
	return test
}


func init() {
	_,_ = onet.GlobalProtocolRegister("CollectiveKeyGeneration", NewCollectiveKeyGeneration)
	_,_ = onet.GlobalProtocolRegister("CollectiveKeySwitching",NewCollectiveKeySwitching)
	_,_ = onet.GlobalProtocolRegister("PublicCollectiveKeySwitching", NewPublicCollectiveKeySwitching)
}


/*****************COLLECTIVE KEY GENERATION ONET HANDLERS *******************/
func (ckgp *CollectiveKeyGenerationProtocol) Start() error {
	log.Lvl4(ckgp.ServerIdentity(), "Started Collective Public Key Generation protocol")

	ckgp.ChannelParams <- StructParameters{ckgp.TreeNode(), ckgp.Params}
	return nil
}



func (ckgp *CollectiveKeyGenerationProtocol) Dispatch() error {

	ckg_0, e := ckgp.CollectiveKeyGeneration()
	if e != nil {
		return e
	}

	log.Lvl4(ckgp.ServerIdentity(), "Completed Collective Public Key Generation protocol ")
	xs := ckg_0.Get()
	log.Lvl4(ckgp.ServerIdentity(), " Got key :", xs[0] ," \n. " , xs[1])




	//for the test - send all to root and in the test check that all keys are equals.

	if Test() {
		//if ! ckgp.IsRoot(){
			err := ckgp.SendTo(ckgp.Root(),ckg_0.Get()[0])

			if err != nil{
				log.Lvl4("Error in key sending to root : " , err)
			}
		//}
		//wait to allow test to get the values.
		<- time.After(time.Second*2)

	}
	log.Lvl4(ckgp.ServerIdentity() , " : im done")
	ckgp.Done()


	return nil
}


func (ckgp *CollectiveKeyGenerationProtocol) Shutdown() error{
	//log.Lvl4(ckgp.ServerIdentity(), ": shutting down.")

	return ckgp.TreeNodeInstance.Shutdown()
}





/** *****************KEY SWITCHING ONET HANDLERS ******************* **/



func (cks *CollectiveKeySwitchingProtocol) Start() error{
	log.Lvl4(cks.ServerIdentity(), "Starting collective key switching for key : " , cks.Params)
	//find a way to take advantage of the unmarshalin

	cks.ChannelParams <- StructSwitchParameters{cks.TreeNode(),SwitchingParameters{cks.Params.Params,cks.Params.SkInputHash,cks.Params.SkOutputHash,cks.Params.Ciphertext}}

	return nil

}


func (cks *CollectiveKeySwitchingProtocol) Dispatch() error{

	//start the key switching

	res, err := cks.CollectiveKeySwitching()
	if err != nil{
		return err
	}
	d , _ := res.MarshalBinary()
	log.Lvl4(cks.ServerIdentity(), " : Resulting ciphertext - " , d[0:25])
	//send it back when testing to check...

	if Test(){
		cks.SendTo(cks.Root(),res)
	}
	if !cks.IsRoot() && Test(){
		cks.Done()
	}

	return nil

}

func (cks *CollectiveKeySwitchingProtocol) Shutdown() error{

	return cks.TreeNodeInstance.Shutdown()


}

/********* PUBLIC KEY SWITCHING ONET HANDLERS ********************/

func (pcks *PublicCollectiveKeySwitchingProtocol) Start() error{
	log.Lvl1(pcks.ServerIdentity(), " starting public collective key switching with parameters : " ,  pcks.Params)

	pcks.ChannelParams <- StructParameters{
		TreeNode: pcks.TreeNode(),
		Params:   pcks.Params,
	}

	pcks.ChannelCiphertext <- StructCiphertext{
		TreeNode:   pcks.TreeNode(),
		Ciphertext: pcks.Ciphertext,
	}
	pcks.ChannelPublicKey <- StructPublicKey{
		TreeNode:  pcks.TreeNode(),
		PublicKey: pcks.PublicKey,
	}
	pcks.ChannelSk <- StructSk{
		TreeNode: pcks.TreeNode(),
		SK : pcks.Sk,
	}


	return nil

}

func (pcks *PublicCollectiveKeySwitchingProtocol) Dispatch() error {

	log.Lvl1("Dispatching ! ")
	res , err := pcks.PublicCollectiveKeySwitching()

	if err != nil{
		log.Fatal("Error : " , err)
	}

	if Test(){
		_ = pcks.SendTo(pcks.Root(),res)
	}

	if !pcks.IsRoot() && Test(){
		pcks.Done()
	}


	return nil

}

func (pcks *PublicCollectiveKeySwitchingProtocol) Shutdown() error{
	return pcks.TreeNodeInstance.Shutdown()
}


