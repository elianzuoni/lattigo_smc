package protocols

import (
	"errors"
	"fmt"
	"github.com/ldsec/lattigo/bfv"
	"github.com/ldsec/lattigo/dbfv"
	"github.com/ldsec/lattigo/ring"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"protocols/utils"
)

//This file is for the collective key switching


//initialize the key switching


func NewCollectiveKeySwitching(n *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {

	p := &CollectiveKeySwitchingProtocol{
		TreeNodeInstance:       n,
	}

	if e := p.RegisterChannels(&p.ChannelParams,  &p.ChannelCKSShare,&p.ChannelCiphertext); e != nil {
		return nil, errors.New("Could not register channel: " + e.Error())
	}

	return p, nil
}

//we use the same parameters as from the collective key generation


/**
input : skInput,skOuput - the key under what ct is encrypted and skOutput the key under what ct will be encrypted.

*/
func (cks *CollectiveKeySwitchingProtocol) CollectiveKeySwitching()(*bfv.Ciphertext,error){
	//if !cks.IsRoot(){
	//	<- time.After(10000*time.Second)
	//}
	cks.Params =(<- cks.ChannelParams).SwitchingParameters





	err := cks.SendToChildren(&SwitchingParameters{cks.Params.Params,cks.Params.SkInputHash,cks.Params.SkOutputHash,cks.Params.Ciphertext})
	if err != nil{
		log.Lvl1("Error : " , err)
		return &bfv.Ciphertext{},err
	}



	bfvContext,err := bfv.NewBfvContextWithParam(&cks.Params.Params)
	SkInput,err := utils.LoadSecretKey(bfvContext,cks.Params.SkInputHash)
	SkOutput , err := utils.LoadSecretKey(bfvContext,cks.Params.SkOutputHash)
	if err != nil{
		return &bfv.Ciphertext{},err
	}



	//sanity test for cipher text sending....
	if cks.IsRoot(){
		c := *bfvContext.NewRandomCiphertext(1)
		err := cks.SendToChildren(&c)
		if err != nil{
			fmt.Print("cant send cipher...",err)
		}
	}else{
		c := (<- cks.ChannelCiphertext).Ciphertext
		fmt.Print("Got cipher ! " , c.Degree())
	}




	key_switch := dbfv.NewCKSProtocol(bfvContext,cks.Params.Params.Sigma)
	h := key_switch.AllocateShare()

	key_switch.GenShare(SkInput.Get(),SkOutput.Get(),&cks.Params.Ciphertext,h)


	if !cks.IsLeaf() {

		for i := 0; i < len(cks.Children()); i++ {
			child := <-cks.ChannelCKSShare
			log.Lvl4(cks.ServerIdentity() ,  " : aggregating !  ")

			//aggregate
			share := dbfv.CKSShare(&ring.Poly{child.Coeffs})
			key_switch.AggregateShares(h,share,h)

		}

	}

	//send to parent.
	log.Lvl4(cks.ServerIdentity() ,  " : sending my h ")
	sending := ring.Poly{h.Coeffs}
	err = cks.SendToParent(&sending)
	log.Lvl4(cks.ServerIdentity() ,  " : sent my h ")

	if err != nil{
		return nil,err
	}







	//propagate the cipher text.
	//the root propagates the cipher text to everyone.
	//this is not strict following of protocol
	res := bfvContext.NewRandomCiphertext(cks.Params.Ciphertext.Degree())
	//TODO here memory error - most likely the cipher is not saved properly.
	if cks.IsRoot() {

		key_switch.KeySwitch(h,&cks.Params.Ciphertext,res)
	} else {
		log.Lvl4("Waiting on cipher text " )
		val := <-cks.ChannelCiphertext
		log.Print(cks.ServerIdentity(), " : " , val.Ciphertext)
		//res = &val.Ciphertext // receive final cipher from parents.
	}

	err = cks.SendToChildren(res)
	// forward the resulting ciphertext to the children
	if err != nil {
		log.Print("Error sending it to children")
		return res, err
	}



	cks.Done()

	return res,nil
}