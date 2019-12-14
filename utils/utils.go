package utils

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/ldsec/lattigo/bfv"
	"github.com/ldsec/lattigo/ring"
	"go.dedis.ch/onet/v3/log"
	"io/ioutil"
	"reflect"
	"strconv"
)

//Save the given secret key with a seed that will be hashed
func SaveSecretKey(sk *bfv.SecretKey, seed string) error {
	data, err := sk.MarshalBinary()

	if err != nil {
		return err
	}
	log.Lvl4("saving file..", seed, " \n ")
	xs := sha256.Sum256([]byte(seed))
	fingerprint := fmt.Sprintf("%x", xs)
	log.Lvl4("Saving a new key. sha : ", fingerprint)

	err = ioutil.WriteFile("SecretKey"+fingerprint, data, 0644)

	if err != nil {
		log.Lvl4("file is not saved...", err)
		return err
	}
	return nil
}

//Load a secret key. Will fail if the key does not exist.
func LoadSecretKey(params bfv.Parameters, seed string) (sk *bfv.SecretKey, err error) {
	var data []byte
	sk = bfv.NewKeyGenerator(&params).NewSecretKey()

	xs := sha256.Sum256([]byte(seed))
	fingerprint := fmt.Sprintf("%x", xs)
	log.Lvl4(seed, " : Loading a key. sha : ", fingerprint)

	if data, err = ioutil.ReadFile("SecretKey" + fingerprint); err != nil {
		return nil, fmt.Errorf("could not read key: %s", err)
	}

	err = sk.UnmarshalBinary(data)
	return
}

//Will try to load the secret key, else will generate a new one.
func GetSecretKey(ctx *bfv.Parameters, seed string) (sk *bfv.SecretKey, err error) {
	log.Lvl3("Loading a key with seed : ", seed)
	if sk, err = LoadSecretKey(*ctx, seed); sk != nil {
		return
	}
	sk = bfv.NewKeyGenerator(ctx).NewSecretKey()

	return sk, SaveSecretKey(sk, seed)
}

//Save the public key so it can be loaded afterwards.
func SavePublicKey(pk *bfv.PublicKey, seed string) error {
	data, err := pk.MarshalBinary()

	if err != nil {
		return err
	}
	log.Lvl4("saving file..", seed, " \n ")
	xs := sha256.Sum256([]byte(seed))
	fingerprint := fmt.Sprintf("%x", xs)
	log.Lvl4("Saving a new key. sha : ", fingerprint)

	err = ioutil.WriteFile("PublicKey"+fingerprint, data, 0644)

	if err != nil {
		log.Lvl4("file is not saved...", err)
		return err
	}
	return nil
}

//Load public key
func LoadPublicKey(ctx *bfv.Parameters, seed string) (pk *bfv.PublicKey, err error) {
	var data []byte

	pk = bfv.NewPublicKey(ctx)

	xs := sha256.Sum256([]byte(seed))
	fingerprint := fmt.Sprintf("%x", xs)
	log.Lvl4("Loading a public key. sha : ", fingerprint)

	if data, err = ioutil.ReadFile("PublicKey" + fingerprint); err != nil {
		return nil, fmt.Errorf("could not read key: %s", err)
	}

	err = pk.UnmarshalBinary(data)
	return
}

//check for errors.
func Check(err error) {
	if err != nil {
		fmt.Printf("error : %v", err)
		return
	}
}

//Compare two polys by marshalling them
func ComparePolys(poly ring.Poly, poly2 ring.Poly) error {

	marsh1, err1 := poly.MarshalBinary()
	if err1 != nil {
		return err1
	}
	marsh2, err2 := poly2.MarshalBinary()
	if err2 != nil {
		return err2
	}

	if !reflect.DeepEqual(marsh1, marsh2) {
		return errors.New("Marshalling of polynoms %v and %v not equal.")
	}
	return nil
}

//Compare two keys by marshalling them.
func CompareKeys(k1 bfv.PublicKey, k2 bfv.PublicKey) error {
	//find more optimal way...
	marsh1, err1 := k1.MarshalBinary()
	if err1 != nil {
		return err1
	}
	marsh2, err2 := k2.MarshalBinary()
	if err2 != nil {
		return err2
	}

	if !reflect.DeepEqual(marsh1, marsh2) {
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

func CompareEvalKeys(keys []bfv.EvaluationKey) error {
	for _, k1 := range keys {
		for _, k2 := range keys {
			for _, e1 := range k1.Get() {
				for _, e2 := range k2.Get() {
					err := CompareArray(e1.Get(), e2.Get())
					if err != nil {
						return err
					}
				}
			}

		}
	}

	return nil
}

func CompareArray(key [][2]*ring.Poly, key2 [][2]*ring.Poly) error {
	if len(key) != len(key2) {
		return errors.New("Non matching length of switching keys")
	}
	for i, _ := range key {
		err := ComparePolys(*key[i][0], *key2[i][0])
		if err != nil {

			return errors.New("Switching key do not match on index : " + strconv.Itoa(i) + "0")
		}
		err = ComparePolys(*key[i][1], *key2[i][1])
		if err != nil {
			return errors.New("Switching key do not match on index : " + strconv.Itoa(i) + "1")
		}

	}

	return nil

}

func Uint64ToBytes(data []uint64) ([]byte, error) {
	padding := data[0]
	//log.Lvl1(padding)
	buf := new(bytes.Buffer)

	xs := data[1:]
	err := binary.Write(buf, binary.LittleEndian, xs)
	if err != nil {
		return []byte{}, err
	}

	//buf.Write(make([]byte,padding))
	result := buf.Bytes()
	result = result[:len(result)-int(padding)]
	return result, nil
}

func BytesToUint64(data []byte) ([]uint64, error) {

	padding := 8 - (len(data) % 8)
	if padding == 8 {
		padding = 0
	}
	array := make([]byte, len(data)+padding)
	copy(array, data)
	buf := bytes.NewBuffer(array)
	result := make([]uint64, (len(data)+7)/8+1)
	result[0] = uint64(padding)
	xs := result[1:]
	err := binary.Read(buf, binary.LittleEndian, &xs)
	if err != nil {
		return []uint64{}, err
	}
	return result, nil
}
