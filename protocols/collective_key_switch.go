package protocols

import (
	"github.com/ldsec/lattigo/bfv"
	"github.com/ldsec/lattigo/dbfv"
	"github.com/ldsec/lattigo/ring"
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




	ctx := ring.NewContext()
	key_switch := dbfv.NewCKS(&params.SkInput,&params.SkOutput,ctx,params.Params.Sigma)

	h := key_switch.KeySwitch(params.cipher.Value()[1]) //TODO Check if cipher[1] = c1 , c0 = cipher[0]


	//TODO re-read this code and make cleaner
	if !cks.IsLeaf() {
		hs := make([]*ring.Poly,len(cks.Children())+1)
		hs = append(hs,h)
		for i := 0; i < len(cks.Children()); i++ {
			child := <-cks.ChannelPublicKey
			hs = append(hs, &child.PublicKey.Poly)

		}

		//aggregate
		if cks.IsRoot(){
			key_switch.Aggregate(params.cipher.Value()[0],hs)
		}else{
			//use an empty cipher text this way it does not add c0 many times.
			tmp := new(bfv.Ciphertext)
			tmp.Value()[0].Zero()

			key_switch.Aggregate(tmp.Value()[0],hs)
			//send your resulting h which is tmp.Value[0]
			err := cks.SendToParent(tmp.Value()[0])
			utils.Check(err)
		}

	}else{
		//if it is a leaf just send h to the parent
		err := cks.SendToParent(h)
		utils.Check(err)
	}







	//propagate the cipher text.
	//the root propagates the cipher text to everyone.
	//this is not strict following of protocol
	//TODO check if ok to do that.
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