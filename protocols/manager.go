package protocols

import (
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
)

var test = true

//Test has a variable test used when you want to test so the protocols sends the result back to the root so you
//can compare the value computed.
func Test() bool {
	return test
}

//TurnOffTest used to turn off the test in a call. Can be used when testing
func TurnOffTest() {
	test = false
}

func init() {
	_, _ = onet.GlobalProtocolRegister("CollectiveKeySwitching", NewCollectiveKeySwitching)
	_, _ = onet.GlobalProtocolRegister("CollectivePublicKeySwitching", NewCollectivePublicKeySwitching)
	_, _ = onet.GlobalProtocolRegister("RelinearizationKeyProtocol", NewRelinearizationKey)
}

/*****************COLLECTIVE KEY GENERATION ONET HANDLERS *******************/

//Start starts the protocol only at root
func (ckgp *CollectiveKeyGenerationProtocol) Start() error {
	log.Lvl1(ckgp.ServerIdentity(), "Started Collective Public Key Generation protocol")

	return nil
}

//Dispatch is called at each node to then run the protocol
func (ckgp *CollectiveKeyGenerationProtocol) Dispatch() error {

	log.Lvl1(ckgp.ServerIdentity(), " Dispatching ; is root = ", ckgp.IsRoot())

	//When running a simulation we need to send a wake up message to the children so all nodes can run!
	log.Lvl1("Sending wake up message")
	err := ckgp.SendToChildren(&Start{})
	if err != nil {
		log.ErrFatal(err, "Could not send wake up message ")
	}

	PublicKey, e := ckgp.CollectiveKeyGeneration()
	if e != nil {
		return e
	}

	log.Lvl1(ckgp.ServerIdentity(), "Completed Collective Public Key Generation protocol ")

	//for the test - send all to root and in the test check that all keys are equals.

	err = ckgp.SendTo(ckgp.Root(), PublicKey.Get()[0])

	if err != nil {
		log.Lvl4("Error in key sending to root : ", err)
	}

	log.Lvl1(ckgp.ServerIdentity(), " : im done")
	if Test() && !ckgp.IsRoot() {
		ckgp.Done()

	}
	//tell the lock we are done.
	ckgp.Cond.Broadcast()

	return nil
}

/** *****************KEY SWITCHING ONET HANDLERS ******************* **/

//Start starts the protocol only at root
func (cks *CollectiveKeySwitchingProtocol) Start() error {
	log.Lvl4(cks.ServerIdentity(), "Starting collective key switching for key : ", cks.Params)
	//find a way to take advantage of the unmarshalin

	//cks.ChannelParams <- StructSwitchParameters{cks.TreeNode(), SwitchingParameters{cks.Params.Params, cks.Params.SkInputHash, cks.Params.SkOutputHash, cks.Params.Ciphertext}}

	return nil

}

//Dispatch is called at each node to then run the protocol
func (cks *CollectiveKeySwitchingProtocol) Dispatch() error {

	//Wake up the nodes
	log.Lvl1("Sending wake up message")
	err := cks.SendToChildren(&Start{})
	if err != nil {
		log.ErrFatal(err, "Could not send wake up message ")
	}

	//start the key switching
	d, _ := cks.Params.Ciphertext.MarshalBinary()
	log.Lvl1("ORIGINAL CIPHER :", d[0:25])
	res, err := cks.CollectiveKeySwitching()
	if err != nil {
		return err
	}
	d, _ = res.MarshalBinary()
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

/********* PUBLIC KEY SWITCHING ONET HANDLERS ********************/

//Start starts the protocol only at root
func (pcks *CollectivePublicKeySwitchingProtocol) Start() error {
	log.Lvl1(pcks.ServerIdentity(), " starting public collective key switching with parameters : ", pcks.Params)

	return nil

}

//Dispatch is called at each node to then run the protocol
func (pcks *CollectivePublicKeySwitchingProtocol) Dispatch() error {

	err := pcks.SendToChildren(&Start{})
	if err != nil {
		log.Error("Could not send start message  : ", err)
		return err
	}
	log.Lvl1("Dispatching ! ")
	res, err := pcks.CollectivePublicKeySwitching()

	if err != nil {
		log.Fatal("Error : ", err)
	}

	if Test() {
		//If test send to root again so we can check at the test program
		_ = pcks.SendTo(pcks.Root(), res)
	}

	if !pcks.IsRoot() && Test() {
		pcks.Done()
	}

	return nil

}

//func (pcks *CollectivePublicKeySwitchingProtocol) Shutdown() error {
//	return pcks.TreeNodeInstance.Shutdown()
//}

/*************RELIN KEY ONET HANDLERS***************/

//Start starts the protocol only at root
func (rlp *RelinearizationKeyProtocol) Start() error {
	log.Lvl1(rlp.ServerIdentity(), " : starting relin key protocol")

	return nil
}

//Dispatch is called at each node to then run the protocol
func (rlp *RelinearizationKeyProtocol) Dispatch() error {
	log.Lvl1(rlp.ServerIdentity(), " : Dispatching for relinearization key protocol! ")
	err := rlp.SendToChildren(&Start{})
	if err != nil {
		log.Error("Error when sending start up message : ", err)
		return err
	}
	res, err := rlp.RelinearizationKey()
	if err != nil {
		log.Error("Error in RLProtocol :  ", err)
		return err
	}

	//small check.
	data, _ := res.MarshalBinary()
	log.Lvl1(rlp.ServerIdentity(), " : got key starting with : ", data[0:25])

	if Test() {
		_ = rlp.SendTo(rlp.Root(), &res)
	}

	if !rlp.IsRoot() && Test() {
		rlp.Done()
	}
	log.Lvl1(rlp.ServerIdentity(), " : exiting dispatch ")
	return nil
}
