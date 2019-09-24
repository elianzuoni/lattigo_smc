package utils

import (
	"fmt"
	"github.com/lca1/lattigo/bfv"
	"io/ioutil"
)

func PrintNewKeyPair() {
	params := bfv.DefaultParams[0]
	ctx, err := bfv.NewBfvContextWithParam(params.N, params.T, params.Qi, params.Pi, params.Sigma)
	if err != nil {
		fmt.Println(err)
		return
	}
	kg := ctx.NewKeyGenerator()
	sk := kg.NewSecretKey()
	fmt.Println(sk.MarshalBinary(ctx))
}

func SaveSecretKey(sk *bfv.SecretKey, ctx *bfv.BfvContext) error {
	data, err := sk.MarshalBinary(ctx)
	if err != nil {
		return err
	}
	return ioutil.WriteFile("secret", data, 0644)
}

func LoadSecretKey(ctx *bfv.BfvContext) (sk *bfv.SecretKey, err error) {
	var data []byte
	sk = ctx.NewKeyGenerator().NewSecretKeyEmpty()
	if data, err = ioutil.ReadFile("secret"); err != nil {
		return nil , fmt.Errorf("could not read key: %s", err)
	}
	err = sk.UnmarshalBinary(data, ctx)
	return
}

func GetSecretKey(ctx *bfv.BfvContext) (sk *bfv.SecretKey, err error) {
	if sk, err = LoadSecretKey(ctx); sk != nil {
		return
	}
	sk = ctx.NewKeyGenerator().NewSecretKey()
	return sk, SaveSecretKey(sk, ctx)
}


//check for errors.
func Check(err error){
	if err != nil{
		fmt.Printf("error : %v", err)
		return
	}

}


