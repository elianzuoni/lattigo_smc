package protocols

import (
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"time"
)

var test = true
//Test has a variable test used when you want to test so the protocols sends the result back to the root so you
//can compare the value computed.
func Test() bool {
	return test
}
func TurnOffTest(){
	test = false
}

func init() {
	_, _ = onet.GlobalProtocolRegister("CollectiveKeySwitching", NewCollectiveKeySwitching)
	_, _ = onet.GlobalProtocolRegister("PublicCollectiveKeySwitching", NewPublicCollectiveKeySwitching)
	_,_ = onet.GlobalProtocolRegister("RelinearizationKeyProtocol",NewRelinearizationKey)
}



/*****************COLLECTIVE KEY GENERATION ONET HANDLERS *******************/
func (ckgp *CollectiveKeyGenerationProtocol) Start() error {
	log.Lvl1(ckgp.ServerIdentity(), "Started Collective Public Key Generation protocol")
	if Test(){
		log.Lvl1("HI")
		ckgp.ChannelParams <- StructParameters{ckgp.TreeNode(), ckgp.Params}
	}


	return nil
}

func (ckgp *CollectiveKeyGenerationProtocol) Dispatch() error {

	log.Lvl1(ckgp.ServerIdentity() , " Dispatch ", ckgp.IsRoot())
	ckg_0, e := ckgp.CollectiveKeyGeneration()
	if e != nil {
		return e
	}

	log.Lvl1(ckgp.ServerIdentity(), "Completed Collective Public Key Generation protocol ")
	xs := ckg_0.Get()
	log.Lvl1(ckgp.ServerIdentity(), " Got key :", xs[0], " \n. ", xs[1])

	//for the test - send all to root and in the test check that all keys are equals.

		err := ckgp.SendTo(ckgp.Root(), ckg_0.Get()[0])

		if err != nil {
			log.Lvl4("Error in key sending to root : ", err)
		}
		<-time.After(time.Second * 2)

	log.Lvl1(ckgp.ServerIdentity(), " : im done")
	ckgp.Done()

	return nil
}

func (ckgp *CollectiveKeyGenerationProtocol) Shutdown() error {
	//log.Lvl4(ckgp.ServerIdentity(), ": shutting down.")

	return ckgp.TreeNodeInstance.Shutdown()
}

/** *****************KEY SWITCHING ONET HANDLERS ******************* **/

func (cks *CollectiveKeySwitchingProtocol) Start() error {
	log.Lvl4(cks.ServerIdentity(), "Starting collective key switching for key : ", cks.Params)
	//find a way to take advantage of the unmarshalin

	cks.ChannelParams <- StructSwitchParameters{cks.TreeNode(), SwitchingParameters{cks.Params.Params, cks.Params.SkInputHash, cks.Params.SkOutputHash, cks.Params.Ciphertext}}

	return nil

}

func (cks *CollectiveKeySwitchingProtocol) Dispatch() error {

	//start the key switching

	res, err := cks.CollectiveKeySwitching()
	if err != nil {
		return err
	}
	d, _ := res.MarshalBinary()
	log.Lvl4(cks.ServerIdentity(), " : Resulting ciphertext - ", d[0:25])
	//send it back when testing to check...

	if Test() {
		cks.SendTo(cks.Root(), res)
	}
	if !cks.IsRoot() && Test() {
		cks.Done()
	}

	return nil

}

func (cks *CollectiveKeySwitchingProtocol) Shutdown() error {

	return cks.TreeNodeInstance.Shutdown()

}

/********* PUBLIC KEY SWITCHING ONET HANDLERS ********************/

func (pcks *PublicCollectiveKeySwitchingProtocol) Start() error {
	log.Lvl1(pcks.ServerIdentity(), " starting public collective key switching with parameters : ", pcks.Params)

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
		SK:       pcks.Sk,
	}

	return nil

}

func (pcks *PublicCollectiveKeySwitchingProtocol) Dispatch() error {

	log.Lvl1("Dispatching ! ")
	res, err := pcks.PublicCollectiveKeySwitching()

	if err != nil {
		log.Fatal("Error : ", err)
	}

	if Test() {
		_ = pcks.SendTo(pcks.Root(), res)
	}

	if !pcks.IsRoot() && Test() {
		pcks.Done()
	}

	return nil

}

func (pcks *PublicCollectiveKeySwitchingProtocol) Shutdown() error {
	return pcks.TreeNodeInstance.Shutdown()
}


/*************RELIN KEY ONET HANDLERS***************/

func (rlp *RelinearizationKeyProtocol) Start()error{
	log.Lvl1(rlp.ServerIdentity() , " : starting relin key protocol")
	//sending the parameters
	//if Test(){
	//
	//	rlp.ChannelSk <- StructSk{
	//		TreeNode: rlp.TreeNode(),
	//		SK:       rlp.Sk,
	//	}
	//	rlp.ChannelParams <- StructParameters{
	//		TreeNode: rlp.TreeNode(),
	//		Params:   rlp.Params,
	//	}
	//	log.Lvl1("Going in A ")
	//	//rlp.ChannelCrp <- StructCrp{
	//	//	TreeNode: rlp.TreeNode(),
	//	//	CRP:        rlp.crp,
	//	//}
	//	log.Lvl1("Got out of A ")
	//}
	log.Lvl1("Done with startup ")

	return nil
}
func (rlp *RelinearizationKeyProtocol) Dispatch()error{
	log.Lvl1(rlp.ServerIdentity() , " : Dispatching for relinearization key protocol! ")
	res, err := rlp.RelinearizationKey()

	//small check.
	data, _ := res.MarshalBinary()
	log.Lvl1(rlp.ServerIdentity(), " : got key starting with : " , data[0:25])

	if err != nil {
		log.Fatal("Error : ", err)
	}

	if Test() {
		_ = rlp.SendTo(rlp.Root(), &res)
	}

	if !rlp.IsRoot() && Test() {
		rlp.Done()
	}
	log.Lvl1(rlp.ServerIdentity() ," : exiting dispatch ")
	return nil
}

