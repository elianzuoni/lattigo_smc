package protocols

import (
	"errors"
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
	params := <- cks.ChannelParams
	//bfvParam := params.Params.Params
	//send parameters to children.
	//N, t uint64, ModulieQ, ModulieP []uint64, sigma float64
	//bfvCtx , err := bfv.NewBfvContextWithParam(bfvParam.N,bfvParam.T,bfvParam.Qi,bfvParam.Pi,bfvParam.Sigma)
	//utils.Check(err)

	//res := params.cipher
	x , _ := params.cipher.MarshalBinary()
	log.Print(cks.ServerIdentity(), " has cipher text : " , x[0:10])

	err1 := cks.SendToChildren(&SwitchingParameters{params.Params,params.SkInputHash,params.SkOutputHash,params.cipher})
	if err1 != nil{
		log.Lvl1("Error : " , err1)
		return &bfv.Ciphertext{},err1
	}



	bfvContext,err := bfv.NewBfvContextWithParam(&params.Params)
	SkInput,err := utils.LoadSecretKey(bfvContext,params.SkInputHash)
	SkOutput , err := utils.LoadSecretKey(bfvContext,params.SkOutputHash)
	if err != nil{
		return &bfv.Ciphertext{},err
	}

	key_switch := dbfv.NewCKSProtocol(bfvContext,params.Params.Sigma)
	h := key_switch.AllocateShare()

	key_switch.GenShare(SkInput.Get(),SkOutput.Get(),&params.cipher,h)


	if !cks.IsLeaf() {

		for i := 0; i < len(cks.Children()); i++ {
			child := <-cks.ChannelCKSShare
			//aggregate
			key_switch.AggregateShares(h,&child.Poly,h)

		}

	}

	//send to parent.
	sending := ring.Poly{h.Coeffs}
	err = cks.SendToParent(&sending)
	if err != nil{
		return nil,err
	}







	//propagate the cipher text.
	//the root propagates the cipher text to everyone.
	//this is not strict following of protocol
	//TODO check if ok to do that.
	res := bfvContext.NewRandomCiphertext(1)
	//TODO here memory error - most likely the cipher is not saved properly.
	if cks.IsRoot() {

		key_switch.KeySwitch(h,&params.cipher,res)
	} else {
		val := (<-cks.ChannelCiphertext)
		res = &val.Ciphertext // receive final cipher from parents.
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