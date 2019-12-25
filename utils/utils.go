package utils

import (
	"errors"
	"fmt"
	"github.com/ldsec/lattigo/bfv"
	"github.com/ldsec/lattigo/dbfv"
	"github.com/ldsec/lattigo/ring"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
	"io/ioutil"
	"os"
	"reflect"
	"strconv"
)

type LocalTest struct {
	Roster          *onet.Roster
	IdealSecretKey0 *bfv.SecretKey
	IdealSecretKey1 *bfv.SecretKey

	SecretKeyShares0 map[network.ServerIdentityID]*bfv.SecretKey
	SecretKeyShares1 map[network.ServerIdentityID]*bfv.SecretKey
	StorageDirectory string
	CrsGen           *ring.CRPGenerator
	Crs              *ring.Poly
}

func GetLocalTestForRoster(roster *onet.Roster, params *bfv.Parameters, directory string) (lt *LocalTest, err error) {
	lt = new(LocalTest)
	lt.IdealSecretKey0 = bfv.NewSecretKey(params) // ideal secret key 0
	lt.IdealSecretKey1 = bfv.NewSecretKey(params)
	lt.Roster = roster
	lt.SecretKeyShares0 = make(map[network.ServerIdentityID]*bfv.SecretKey)
	lt.SecretKeyShares1 = make(map[network.ServerIdentityID]*bfv.SecretKey)
	lt.StorageDirectory = directory

	lt.CrsGen = dbfv.NewCRPGenerator(params, []byte{'l', 'a', 't', 't', 'i', 'g', 'o'})
	lt.Crs = lt.CrsGen.ClockNew()

	rq, _ := ring.NewContextWithParams(1<<params.LogN, append(params.Moduli.Qi, params.Moduli.Pi...))
	for _, si := range roster.List {
		lt.SecretKeyShares0[si.ID], err = GetSecretKey(params, si.ID, directory+"sk0")
		d, _ := lt.SecretKeyShares0[si.ID].MarshalBinary()
		log.Lvl2(si.ID, "share 0 ", d[0:25])
		if err != nil {
			return
		}
		rq.Add(lt.IdealSecretKey0.Get(), lt.SecretKeyShares0[si.ID].Get(), lt.IdealSecretKey0.Get())

		lt.SecretKeyShares1[si.ID], err = GetSecretKey(params, si.ID, directory+"sk1")
		d, _ = lt.SecretKeyShares1[si.ID].MarshalBinary()
		log.Lvl2(si.ID, "share 1 ", d[0:25])
		if err != nil {
			return
		}
		rq.Add(lt.IdealSecretKey1.Get(), lt.SecretKeyShares1[si.ID].Get(), lt.IdealSecretKey1.Get())

	}
	return
}

func (lt *LocalTest) TearDown(simul bool) error {
	var err error

	for _, si := range lt.Roster.List {
		keyfileName := si.ID.String() + ".sk"
		log.Lvl3("cleaning:", keyfileName)
		if simul {
			err = os.Remove("../" + lt.StorageDirectory + "sk0" + keyfileName)

		} else {
			err = os.Remove(lt.StorageDirectory + "sk0" + keyfileName)
		}
		if err != nil {

			return err
		}
		if simul {
			err = os.Remove("../" + lt.StorageDirectory + "sk1" + keyfileName)

		} else {
			err = os.Remove(lt.StorageDirectory + "sk1" + keyfileName)

		}
		if err != nil {
			return err
		}
	}
	return nil
}

//Save the given secret key with a seed that will be hashed
func SaveSecretKey(sk *bfv.SecretKey, seed network.ServerIdentityID, directory string) error {
	data, err := sk.MarshalBinary()
	if err != nil {
		return err
	}
	err = CreateDirIfNotExist(directory)
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(directory+seed.String()+".sk", data, 0644)
	if err != nil {
		log.Error("file is not saved...", err)

		return err
	}

	return nil
}

//CreateDirIfNotExist creates a directory if it does not exist.
func CreateDirIfNotExist(dir string) error {
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		err = os.MkdirAll(dir, 0755)
		if err != nil {
			return err
		}
	}

	return nil
}

//Load a secret key. Will fail if the key does not exist.
func LoadSecretKey(params bfv.Parameters, seed network.ServerIdentityID, directory string) (sk *bfv.SecretKey, err error) {
	var data []byte
	sk = bfv.NewKeyGenerator(&params).NewSecretKey()

	if data, err = ioutil.ReadFile(directory + seed.String() + ".sk"); err != nil {
		return nil, fmt.Errorf("could not read key: %s", err)
	}
	err = sk.UnmarshalBinary(data)
	return
}

//Will try to load the secret key, else will generate a new one.
func GetSecretKey(ctx *bfv.Parameters, seed network.ServerIdentityID, directory string) (sk *bfv.SecretKey, err error) {
	log.Lvl3("Loading a key with seed : ", seed)
	if sk, err = LoadSecretKey(*ctx, seed, directory); sk != nil {
		return
	}
	sk = bfv.NewKeyGenerator(ctx).NewSecretKey()

	return sk, SaveSecretKey(sk, seed, directory)
}

//Save the public key so it can be loaded afterwards.
func SavePublicKey(pk *bfv.PublicKey, seed network.ServerIdentityID) error {
	data, err := pk.MarshalBinary()

	if err != nil {
		return err
	}
	err = ioutil.WriteFile(seed.String()+"pk", data, 0644)
	if err != nil {
		log.Lvl4("file is not saved...", err)
		return err
	}
	return nil
}

//Load public key
func LoadPublicKey(ctx *bfv.Parameters, seed network.ServerIdentityID) (pk *bfv.PublicKey, err error) {
	var data []byte
	pk = bfv.NewPublicKey(ctx)
	if data, err = ioutil.ReadFile(seed.String() + "pk"); err != nil {
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
