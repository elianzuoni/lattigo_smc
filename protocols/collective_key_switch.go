package protocols

import (
	"github.com/lca1/lattigo/bfv"
	"github.com/lca1/lattigo/dbfv"
	"github.com/lca1/lattigo/ring"
	"go.dedis.ch/onet/v3/log"
	"protocols/utils"
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
	bfvParam := params.Params.Params
	//send parameters to children.
	//N, t uint64, ModulieQ, ModulieP []uint64, sigma float64
	//bfvCtx , err := bfv.NewBfvContextWithParam(bfvParam.N,bfvParam.T,bfvParam.Qi,bfvParam.Pi,bfvParam.Sigma)
	//utils.Check(err)

	//TODO check degree how to get it.
	res := params.cipher

	err1 := cks.SendToChildrenInParallel(&SwitchingParameters{params.Params,params.Skinput,params.SkOutput,params.cipher})
	if err1 != nil{
		log.Lvl1("Error : " , err1)
		return &res,err1[0]
	}




	ctx := ring.NewContext()
	key_switch := dbfv.NewCKS(&params.Skinput,&params.SkOutput,ctx,params.Params.Params.Sigma)

	h := key_switch.KeySwitch(params.cipher.Value()[1]) //TODO Check if [1] = c1 , c0 = [0]

	//aggregate only if root -> because otherwise c0 is added many times !


	if !cks.IsRoot() {
		hs := make([]*ring.Poly,len(cks.Children())+1)
		hs = append(hs,h)
		for i := 0; i < len(cks.Children()); i++ {
			child := <-cks.ChannelPublicKey
			hs = append(hs, &child.PublicKey.Poly)
		}

		//aggregate
		key_switch.Aggregate(params.cipher.Value()[0],hs)

	}


	//propagate the cipher text.
	//the root propagates the cipher text to everyone.
	//this is not a purely decentralized way of doing
	//TODO check if ok
	if cks.IsRoot() {
		res = params.cipher //root already has the cipher
	} else {
		res = (<-cks.ChannelCiphertext).Ciphertext // receive final cipher from parents.
	}

	err := cks.SendToChildren(&res)
	// forward the resulting ciphertext to the children
	if err != nil {
		return &res, err
	}




	return &res,nil
}