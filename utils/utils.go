package utils

import (
	"fmt"
	"github.com/ldsec/lattigo/bfv"
	"io/ioutil"
)

func PrintNewKeyPair() {
	params := bfv.DefaultParams[0]
	ctx, err := bfv.NewBfvContextWithParam(&params)
	if err != nil {
		fmt.Println(err)
		return
	}
	kg := ctx.NewKeyGenerator()
	//TODO p = 0 here
	sk , err := kg.NewSecretKey(0.5)
	if err != nil {
		fmt.Printf("Error : %v \n", err)
	}
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
	p := 0.5
	sk,err = ctx.NewKeyGenerator().NewSecretKey(p)
	if err != nil {
		return nil, err
	}
	if data, err = ioutil.ReadFile("secret"); err != nil {
		return nil , fmt.Errorf("could not read key: %s", err)
	}

	err = sk.UnmarshalBinary(data,ctx)
	return
}

func GetSecretKey(ctx *bfv.BfvContext) (sk *bfv.SecretKey, err error) {
	if sk, err = LoadSecretKey(ctx); sk != nil {
		return
	}
	//TODO p = 0.5 here

	sk,err = ctx.NewKeyGenerator().NewSecretKey(0.5)
	if err != nil{
		return nil, err
	}
	return sk, SaveSecretKey(sk, ctx)
}


//check for errors.
func Check(err error){
	if err != nil{
		fmt.Printf("error : %v", err)
		return
	}

}


