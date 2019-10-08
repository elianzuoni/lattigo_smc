package utils

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"github.com/ldsec/lattigo/bfv"
	"github.com/ldsec/lattigo/ring"
	"go.dedis.ch/onet/v3/log"
	"io/ioutil"
	"reflect"
)

func PrintNewKeyPair() {
	params := bfv.DefaultParams[0]
	ctx, err := bfv.NewBfvContextWithParam(&params)
	if err != nil {
		fmt.Println(err)
		return
	}
	kg := ctx.NewKeyGenerator()
	//TODO p = 0.3 here
	sk  := kg.NewSecretKey()
	if err != nil {
		fmt.Printf("Error : %v \n", err)
	}
	fmt.Println(sk.MarshalBinary())
}

func SaveSecretKey(sk *bfv.SecretKey, ctx *bfv.BfvContext,seed string) error {
	data, err := sk.MarshalBinary()

	if err != nil {
		return err
	}
	log.Lvl4("saving file..",seed, " \n ")
	xs := sha256.Sum256([]byte(seed))
	fingerprint := fmt.Sprintf("%x", xs)
	log.Lvl4("Saving a new key. sha : " , fingerprint)

	err = ioutil.WriteFile("SecretKey"+fingerprint, data, 0644)

	if err != nil{
		log.Lvl4("file is not saved...",err)
		return err
	}
	return nil
}

func LoadSecretKey(ctx *bfv.BfvContext,seed string) (sk *bfv.SecretKey, err error) {
	var data []byte
	sk = ctx.NewKeyGenerator().NewSecretKey()



	xs := sha256.Sum256([]byte(seed))
	fingerprint := fmt.Sprintf("%x", xs)
	log.Lvl4(seed , " : Loading a key. sha : " , fingerprint)

	if data, err = ioutil.ReadFile("SecretKey"+fingerprint); err != nil {
		return nil , fmt.Errorf("could not read key: %s", err)
	}

	err = sk.UnmarshalBinary(data)
	return
}

func GetSecretKey(ctx *bfv.BfvContext,seed string) (sk *bfv.SecretKey, err error) {
	if sk, err = LoadSecretKey(ctx,seed); sk != nil {
		return
	}

	sk = ctx.NewKeyGenerator().NewSecretKey()

	return sk, SaveSecretKey(sk, ctx,seed)
}

//Save the public key so it can be loaded afterwards.
func SavePublicKey(pk *bfv.PublicKey, ctx *bfv.BfvContext,seed string) error {
	data, err := pk.MarshalBinary()

	if err != nil {
		return err
	}
	log.Lvl4("saving file..",seed, " \n ")
	xs := sha256.Sum256([]byte(seed))
	fingerprint := fmt.Sprintf("%x", xs)
	log.Lvl4("Saving a new key. sha : " , fingerprint)

	err = ioutil.WriteFile("PublicKey"+fingerprint, data, 0644)

	if err != nil{
		log.Lvl4("file is not saved...",err)
		return err
	}
	return nil
}
//Load public key
func LoadPublicKey(ctx *bfv.BfvContext, seed string)(pk *bfv.PublicKey, err error){
	var data []byte
	pk = ctx.NewPublicKey()


	xs := sha256.Sum256([]byte(seed))
	fingerprint := fmt.Sprintf("%x", xs)
	log.Lvl4("Loading a public key. sha : " , fingerprint)

	if data, err = ioutil.ReadFile("PublicKey"+fingerprint); err != nil {
		return nil , fmt.Errorf("could not read key: %s", err)
	}

	err = pk.UnmarshalBinary(data)
	return
}



//check for errors.
func Check(err error){
	if err != nil{
		fmt.Printf("error : %v", err)
		return
	}
}

func ComparePolys(poly ring.Poly, poly2 ring.Poly) error {

	marsh1,err1 := poly.MarshalBinary()
	if err1 != nil{
		return err1
	}
	marsh2, err2 := poly2.MarshalBinary()
	if err2 != nil{
		return err2
	}

	if !reflect.DeepEqual(marsh1,marsh2) {
		return errors.New("Marshalling of polynoms %v and %v not equal.")
	}
	return nil
}

func CompareKeys(k1 bfv.PublicKey, k2 bfv.PublicKey) error {
	//find more optimal way...
	marsh1,err1 := k1.MarshalBinary()
	if err1 != nil{
		return err1
	}
	marsh2, err2 := k2.MarshalBinary()
	if err2 != nil{
		return err2
	}

	if !reflect.DeepEqual(marsh1,marsh2) {
		return errors.New("Marshalling of polynoms %v and %v not equal.")
	}
	return nil
}



// equalslice compares two slices of uint64 values, and return true if they are equal, else false.
func Equalslice(a, b []uint64) bool {

	if len(a) != len(b) {
		return false
	}

	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
