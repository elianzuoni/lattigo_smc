//Some utility methods that simplify the testing process.
package utils

import (
	"bytes"
	"encoding/binary"
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
	"strconv"
	"strings"
)

//LocalTest a structure containing the shares and ideal secret keys. Should be used for testing.
type LocalTest struct {
	Roster          *onet.Roster
	Params          *bfv.Parameters
	IdealSecretKey0 *bfv.SecretKey
	IdealSecretKey1 *bfv.SecretKey

	SecretKeyShares0 map[network.ServerIdentityID]*bfv.SecretKey
	SecretKeyShares1 map[network.ServerIdentityID]*bfv.SecretKey
	StorageDirectory string
	CrsGen           *ring.CRPGenerator
	Crs              *ring.Poly
	crsCipherGen     *ring.CRPGenerator
}

//GetLocalTestForRoster gets the local test for the given roster. The keys will be stored in directory.
func GetLocalTestForRoster(roster *onet.Roster, params *bfv.Parameters, directory string) (lt *LocalTest, err error) {
	lt = new(LocalTest)
	lt.Params = params
	lt.IdealSecretKey0 = bfv.NewSecretKey(params) // ideal secret key 0
	lt.IdealSecretKey1 = bfv.NewSecretKey(params)
	lt.Roster = roster
	lt.SecretKeyShares0 = make(map[network.ServerIdentityID]*bfv.SecretKey)
	lt.SecretKeyShares1 = make(map[network.ServerIdentityID]*bfv.SecretKey)
	lt.StorageDirectory = directory

	lt.CrsGen = dbfv.NewCRPGenerator(params, []byte{'l', 'a', 't', 't', 'i', 'g', 'o'})
	lt.Crs = lt.CrsGen.ClockNew()
	lt.crsCipherGen = dbfv.NewCipherCRPGenerator(params, []byte{'s', 'o', 'r', 'e', 't', 'a'})

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

//TearDown removes the local key stored in the filesystem.
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

//SaveSecretKey the given secret key with a seed that will be hashed
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
	sk = bfv.NewKeyGenerator(&params).GenSecretKey()

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
	sk = bfv.NewKeyGenerator(ctx).GenSecretKey()

	return sk, SaveSecretKey(sk, seed, directory)
}

//SavePublicKey so it can be loaded afterwards.
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

//LoadPublicKey loads a public key from the seed.
func LoadPublicKey(ctx *bfv.Parameters, seed network.ServerIdentityID) (pk *bfv.PublicKey, err error) {
	var data []byte
	pk = bfv.NewPublicKey(ctx)
	if data, err = ioutil.ReadFile(seed.String() + "pk"); err != nil {
		return nil, fmt.Errorf("could not read key: %s", err)
	}

	err = pk.UnmarshalBinary(data)
	return
}

//Equalslice compares two slices of uint64 values, and return true if they are equal, else false.
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

//Uint64ToBytes converst a uint64 array to byte array. naive true will do a 1-to-1 mapping of array else 1-to-8 mapping
func Uint64ToBytes(data []uint64, naive bool) ([]byte, error) {
	if naive {
		res := make([]byte, len(data))
		for i, e := range data {
			res[i] = byte(e)

		}
		return res, nil
	}
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

//BytesToUint64 byte array to uint64 array. naive true means a 1-to-1 mapping. false 8-to-1 mapping
func BytesToUint64(data []byte, naive bool) ([]uint64, error) {
	if naive {
		res := make([]uint64, len(data))
		for i, e := range data {
			res[i] = uint64(e)
		}

		return res, nil
	}

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

func StringToBytes(str []string) []byte {
	data := make([]byte, len(str))
	for i, e := range str {
		v, err := strconv.ParseInt(e, 10, 8)
		if err != nil {
			panic(err)
		}
		data[i] = byte(v)

	}
	return data
}

//SendISMOthers sends a message to all other service. !! THIS IS TAKEN FROM Unlynx ( https://github.com/ldsec/unlynx ) !!
func SendISMOthers(s *onet.ServiceProcessor, el *onet.Roster, msg interface{}) error {
	var errStrs []string
	for _, e := range el.List {
		if !e.ID.Equal(s.ServerIdentity().ID) {
			log.Lvl3("Sending to", e)
			err := s.SendRaw(e, msg)
			if err != nil {
				errStrs = append(errStrs, err.Error())
			}
		}
	}
	var err error
	if len(errStrs) > 0 {
		err = errors.New(strings.Join(errStrs, "\n"))
	}
	return err
}

// GenMsgCtAccum is used for testing encryption-to-shares: it creates a random message and its encryption,
// and allocates an AdditiveShare accumulator.
func (lt *LocalTest) GenMsgCtAccum() (msg []uint64, ct *bfv.Ciphertext, accum *dbfv.ConcurrentAdditiveShareAccum) {
	contextT, _ := ring.NewContextWithParams(uint64(1<<lt.Params.LogN), []uint64{lt.Params.T})
	poly := contextT.NewUniformPoly()
	msg = poly.Coeffs[0]
	encoder := bfv.NewEncoder(lt.Params)
	plain := bfv.NewPlaintext(lt.Params)
	encoder.EncodeUint(msg, plain)
	encryptor := bfv.NewEncryptorFromSk(lt.Params, lt.IdealSecretKey0)
	ct = bfv.NewCiphertext(lt.Params, 1)
	encryptor.Encrypt(plain, ct)

	accum = dbfv.NewConcurrentAdditiveShareAccum(lt.Params, lt.Params.Sigma, len(lt.Roster.List))
	return
}

// NewCipherCRS returns a new crp for ciphertext (Sampled from R_q)
func (lt *LocalTest) NewCipherCRS() *ring.Poly {
	return lt.crsCipherGen.ClockNew()
}
