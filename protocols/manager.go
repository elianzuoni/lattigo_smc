package protocols

import (
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"protocols/utils"
	"time"
)

var test = true

func Test() bool {
	return test
}


func init() {
	onet.GlobalProtocolRegister("CollectiveKeyGeneration", NewCollectiveKeyGeneration)
	onet.GlobalProtocolRegister("CollectiveKeySwitching",NewCollectiveKeySwitching)
	onet.GlobalProtocolRegister("PublicCollectiveKeySwitching", NewPublicCollectiveKeySwitching)
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

	//log.Lvl4(ckgp.ServerIdentity(), "Completed Collective Public Key Generation protocol ")
	xs := ckg_0.Get()
	log.Lvl4(ckgp.ServerIdentity(), " Got key :", xs[0] ," \n. " , xs[1])




	//TODO turn off in real scenario..
	//for the test - send all to root and in the test check that all keys are equals.

	if test {
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
	ckgp.TreeNodeInstance.Shutdown()
	return nil
}





/** *****************KEY SWITCHING ONET HANDLERS ******************* **/



func (cks *CollectiveKeySwitchingProtocol) Start() error{
	log.Lvl4(cks.ServerIdentity(), "Starting collective key switching for key : " , cks.Params)
	//TODO Here only the master node gets access to the ciphertext
	//find a way to take advantage of the unmarshalin

	cks.ChannelParams <- StructSwitchParameters{cks.TreeNode(),SwitchingParameters{cks.Params.Params,cks.Params.SkInputHash,cks.Params.SkOutputHash,cks.Params.Ciphertext}}

	return nil

}


func (cks *CollectiveKeySwitchingProtocol) Dispatch() error{

	//start the key switching

	res, err := cks.CollectiveKeySwitching()
	utils.Check(err)
	d , _ := res.MarshalBinary()
	log.Lvl4(cks.ServerIdentity(), " : Resulting ciphertext - " , d[0:25])
	//send it back when testing to check...

	if test{
		cks.SendTo(cks.Root(),res)
	}
	if !cks.IsRoot() && test{
		cks.Done()
	}

	return nil

}

func (cks *CollectiveKeySwitchingProtocol) Shutdown() error{
	cks.TreeNodeInstance.Shutdown()
	return nil


}

/********* PUBLIC KEY SWITCHING ONET HANDLERS ********************/

func (pcks *PublicCollectiveKeySwitchingProtocol) Start() error{
	log.Lvl4(pcks.ServerIdentity(), " starting public collective key switching with parameters : " ,  pcks.Params)

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
		SK : SK{pcks.Sk},
	}


	return nil

}

func (pcks *PublicCollectiveKeySwitchingProtocol) Dispatch() error {

	log.Lvl1("Dispatching ! ")
	res , err := pcks.PublicCollectiveKeySwitching()

	if err != nil{
		log.Fatal("Error : " , err)
	}
	return nil
	if test{
		pcks.SendTo(pcks.Root(),res)
	}
	if !pcks.IsRoot() && test{
		pcks.Done()
	}


	return nil

}

func (pcks *PublicCollectiveKeySwitchingProtocol) Shutdown() error{
	return pcks.TreeNodeInstance.Shutdown()
}


