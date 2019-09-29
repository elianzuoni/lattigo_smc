package protocols

import (
	"github.com/ldsec/lattigo/bfv"
	"github.com/ldsec/lattigo/dbfv"
	"go.dedis.ch/onet/v3/log"
)

//This file is for the collective key switching


//initialize the key switching

func init(){



}

//we use the same parameters as from the collective key generation


/**
input : skInput,skOuput - the key under what ct is encrypted and skOutput the key under what ct will be encrypted.

*/
func (cks *CollectiveKeySwitchingProtocol) CollectiveKeySwitching()(*bfv.Ciphertext,error){

	params := <- cks.ChannelParams
	//bfvParam := params.Params.Params
	//send parameters to children.
	//N, t uint64, ModulieQ, ModulieP []uint64, sigma float64
	//bfvCtx , err := bfv.NewBfvContextWithParam(bfvParam.N,bfvParam.T,bfvParam.Qi,bfvParam.Pi,bfvParam.Sigma)
	//utils.Check(err)

	res := params.cipher

	err1 := cks.SendToChildren(&SwitchingParameters{params.Params,params.SkInput,params.SkOutput,params.cipher})
	if err1 != nil{
		log.Lvl1("Error : " , err1)
		return &res,err1
	}




	ctx,err := bfv.NewBfvContextWithParam(&params.Params)
	if err != nil{
		return &bfv.Ciphertext{},err
	}

	key_switch := dbfv.NewCKSProtocol(ctx,params.Params.Sigma)
	h := key_switch.AllocateShare()
	key_switch.GenShare(&params.SkInput,&params.SkOutput,&params.cipher,h)


	if !cks.IsLeaf() {

		for i := 0; i < len(cks.Children()); i++ {
			child := <-cks.ChannelCKSShare
			//aggregate
			key_switch.AggregateShares(h,&child.Poly,h)

		}

	}

	//send to parent.
	err = cks.SendToParent(h)
	if err != nil{
		return nil,err
	}







	//propagate the cipher text.
	//the root propagates the cipher text to everyone.
	//this is not strict following of protocol
	//TODO check if ok to do that.
	if cks.IsRoot() {
		res := bfv.Ciphertext{}

		key_switch.KeySwitch(h,&params.cipher,&res)
	} else {
		res = (<-cks.ChannelCiphertext).Ciphertext // receive final cipher from parents.
	}

	err = cks.SendToChildren(&res)
	// forward the resulting ciphertext to the children
	if err != nil {
		return &res, err
	}




	return &res,nil
}