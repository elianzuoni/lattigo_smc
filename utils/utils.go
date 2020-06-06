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
	"go.dedis.ch/protobuf"
	uuid "gopkg.in/satori/go.uuid.v1"
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
	Ciphertext      *bfv.Ciphertext

	SecretKeyShares0 map[network.ServerIdentityID]*bfv.SecretKey
	SecretKeyShares1 map[network.ServerIdentityID]*bfv.SecretKey
	StorageDirectory string
	CRS              *ring.Poly
	CipherCRS        *ring.Poly
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
	_, lt.Ciphertext, _ = lt.GenMsgCtAccum()

	crsGen := dbfv.NewCRPGenerator(params, []byte{'l', 'a', 't', 't', 'i', 'g', 'o'})
	lt.CRS = crsGen.ClockNew()
	crsCipherGen := dbfv.NewCipherCRPGenerator(params, []byte{'s', 'o', 'r', 'e', 't', 'a'})
	lt.CipherCRS = crsCipherGen.ClockNew()

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

//Broadcast sends a message to all nodes (self included)
func Broadcast(s *onet.ServiceProcessor, el *onet.Roster, msg interface{}) error {
	var errStrs []string
	for _, e := range el.List {
		log.Lvl3("Sending to", e)
		err := s.SendRaw(e, msg)
		if err != nil {
			errStrs = append(errStrs, err.Error())
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
func (lt *LocalTest) GenMsgCtAccum() (msg []uint64, ct *bfv.Ciphertext, accum *ConcurrentAdditiveShareAccum) {
	contextT, _ := ring.NewContextWithParams(uint64(1<<lt.Params.LogN), []uint64{lt.Params.T})
	poly := contextT.NewUniformPoly()
	msg = poly.Coeffs[0]
	encoder := bfv.NewEncoder(lt.Params)
	plain := bfv.NewPlaintext(lt.Params)
	encoder.EncodeUint(msg, plain)
	encryptor := bfv.NewEncryptorFromSk(lt.Params, lt.IdealSecretKey0)
	ct = bfv.NewCiphertext(lt.Params, 1)
	encryptor.Encrypt(plain, ct)

	accum = NewConcurrentAdditiveShareAccum(lt.Params, lt.Params.Sigma, len(lt.Roster.List))
	return
}

func (lt *LocalTest) MarshalBinary() (data []byte, err error) {
	// Marshal Roster
	rosData, err := protobuf.Encode(lt.Roster)
	if err != nil {
		return
	}
	rosLen := len(rosData)

	// Marshal Params
	parData, err := lt.Params.MarshalBinary()
	if err != nil {
		return
	}
	parLen := len(parData)

	// Marshal IdealSecretKey0
	isk0Data, err := lt.IdealSecretKey0.MarshalBinary()
	if err != nil {
		return
	}
	isk0Len := len(isk0Data)

	// Marshal IdealSecretKey1
	isk1Data, err := lt.IdealSecretKey1.MarshalBinary()
	if err != nil {
		return
	}
	isk1Len := len(isk1Data)

	// Marshal Ciphertext
	ctData, err := lt.Ciphertext.MarshalBinary()
	if err != nil {
		return
	}
	ctLen := len(ctData)

	// Marshal SecretKeyShares0
	sks0Data, err := marshalKeyMap(lt.SecretKeyShares0)
	if err != nil {
		return
	}
	sks0Len := len(sks0Data)

	// Marshal SecretKeyShares1
	sks1Data, err := marshalKeyMap(lt.SecretKeyShares1)
	if err != nil {
		return
	}
	sks1Len := len(sks1Data)

	// Marshal CRS
	crsData, err := lt.CRS.MarshalBinary()
	if err != nil {
		return
	}
	crsLen := len(crsData)

	// Marshal CipherCRS
	ccrsData, err := lt.CipherCRS.MarshalBinary()
	if err != nil {
		return
	}
	ccrsLen := len(ccrsData)

	// Build data as [<rosLen>, <parLen>, <isk0Len>, <isk1Len>, <ctLen>, <sks0Len>, <sks1Len>, <crsLen>, <ccrsLen>,
	// <Roster>, <Params>, <IdealSK0>, <IdealSK1>, <Ciphertext>, <SecretSKs0>, <SecretSKs1>, <CRS>, <CipherCRS>]
	data = make([]byte, 9*8+rosLen+parLen+isk0Len+isk1Len+ctLen+sks0Len+sks1Len+crsLen+ccrsLen)
	ptr := 0 // Used to index data
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(rosLen))
	ptr += 8
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(parLen))
	ptr += 8
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(isk0Len))
	ptr += 8
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(isk1Len))
	ptr += 8
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(ctLen))
	ptr += 8
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(sks0Len))
	ptr += 8
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(sks1Len))
	ptr += 8
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(crsLen))
	ptr += 8
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(ccrsLen))
	ptr += 8
	copy(data[ptr:ptr+rosLen], rosData)
	ptr += rosLen
	copy(data[ptr:ptr+parLen], parData)
	ptr += parLen
	copy(data[ptr:ptr+isk0Len], isk0Data)
	ptr += isk0Len
	copy(data[ptr:ptr+isk1Len], isk1Data)
	ptr += isk1Len
	copy(data[ptr:ptr+ctLen], ctData)
	ptr += ctLen
	copy(data[ptr:ptr+sks0Len], sks0Data)
	ptr += sks0Len
	copy(data[ptr:ptr+sks1Len], sks1Data)
	ptr += sks1Len
	copy(data[ptr:ptr+crsLen], crsData)
	ptr += crsLen
	copy(data[ptr:ptr+ccrsLen], ccrsData)
	ptr += ccrsLen

	return
}
func (lt *LocalTest) UnmarshalBinary(data []byte) (err error) {
	ptr := 0 // Used to index data

	// Read lengths
	rosLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8
	parLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8
	isk0Len := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8
	isk1Len := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8
	ctLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8
	sks0Len := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8
	sks1Len := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8
	crsLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8
	ccrsLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8

	// Read Roster
	if rosLen > 0 {
		if lt.Roster == nil {
			lt.Roster = &onet.Roster{}
		}
		err = protobuf.Decode(data[ptr:ptr+rosLen], lt.Roster)
		ptr += rosLen
		if err != nil {
			return
		}
	}

	// Read Parameters
	if parLen > 0 {
		if lt.Params == nil {
			lt.Params = &bfv.Parameters{}
		}
		err = lt.Params.UnmarshalBinary(data[ptr : ptr+parLen])
		ptr += parLen
		if err != nil {
			return
		}
	}

	// Read IdealSecretKey0
	if isk0Len > 0 {
		if lt.IdealSecretKey0 == nil {
			lt.IdealSecretKey0 = &bfv.SecretKey{}
		}
		err = lt.IdealSecretKey0.UnmarshalBinary(data[ptr : ptr+isk0Len])
		ptr += isk0Len
		if err != nil {
			return
		}
	}

	// Read IdealSecretKey1
	if isk1Len > 0 {
		if lt.IdealSecretKey1 == nil {
			lt.IdealSecretKey1 = &bfv.SecretKey{}
		}
		err = lt.IdealSecretKey1.UnmarshalBinary(data[ptr : ptr+isk1Len])
		ptr += isk1Len
		if err != nil {
			return
		}
	}

	// Read Ciphertext
	if ctLen > 0 {
		if lt.Ciphertext == nil {
			lt.Ciphertext = &bfv.Ciphertext{}
		}
		err = lt.Ciphertext.UnmarshalBinary(data[ptr : ptr+ctLen])
		ptr += ctLen
		if err != nil {
			return
		}
	}

	// Read SecretKeyShares0
	if sks0Len > 0 {
		lt.SecretKeyShares0, err = unmarshalKeyMap(data[ptr : ptr+sks0Len])
		ptr += sks0Len
		if err != nil {
			return
		}
	}

	// Read SecretKeyShares1
	if sks1Len > 0 {
		lt.SecretKeyShares1, err = unmarshalKeyMap(data[ptr : ptr+sks1Len])
		ptr += sks1Len
		if err != nil {
			return
		}
	}

	// Read CRS
	if crsLen > 0 {
		if lt.CRS == nil {
			lt.CRS = &ring.Poly{}
		}
		err = lt.CRS.UnmarshalBinary(data[ptr : ptr+crsLen])
		ptr += crsLen
		if err != nil {
			return
		}
	}

	// Read CipherCRS
	if ccrsLen > 0 {
		if lt.CipherCRS == nil {
			lt.CipherCRS = &ring.Poly{}
		}
		err = lt.CipherCRS.UnmarshalBinary(data[ptr : ptr+ccrsLen])
		ptr += ccrsLen
		if err != nil {
			return
		}
	}

	return
}

func marshalKeyMap(keyMap map[network.ServerIdentityID]*bfv.SecretKey) (data []byte, err error) {
	keysData := make(map[network.ServerIdentityID][]byte)
	valuesData := make(map[network.ServerIdentityID][]byte)

	// Marshal Keys and Values
	mapLen := 0
	for key, value := range keyMap {
		keysData[key], err = uuid.UUID(key).MarshalBinary()
		if err != nil {
			return
		}
		valuesData[key], err = value.MarshalBinary()
		if err != nil {
			return
		}
		mapLen += 8 + len(keysData[key]) + 8 + len(valuesData[key])
	}

	// Build data as [<nEntries>, (<keyLen>, <key>, <valueLen>, <value>)*]
	data = make([]byte, 8+mapLen)
	ptr := 0 // Used to index data
	binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(len(keyMap)))
	ptr += 8
	for key, _ := range keyMap {
		binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(len(keysData[key])))
		ptr += 8
		copy(data[ptr:ptr+len(keysData[key])], keysData[key])
		ptr += len(keysData[key])
		binary.BigEndian.PutUint64(data[ptr:ptr+8], uint64(len(valuesData[key])))
		ptr += 8
		copy(data[ptr:ptr+len(valuesData[key])], valuesData[key])
		ptr += len(valuesData[key])
	}

	return
}
func unmarshalKeyMap(data []byte) (keyMap map[network.ServerIdentityID]*bfv.SecretKey, err error) {
	ptr := 0 // Used to index data
	keyMap = make(map[network.ServerIdentityID]*bfv.SecretKey)

	// Read nEntries
	nEntries := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
	ptr += 8

	// Read KeyMap
	for i := 0; i < nEntries; i++ {
		// Read keyLen
		keyLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
		ptr += 8
		// Read key
		var id uuid.UUID
		if keyLen > 0 {
			err = id.UnmarshalBinary(data[ptr : ptr+keyLen])
			ptr += keyLen
			if err != nil {
				return
			}
		}

		// Read valueLen
		valueLen := int(binary.BigEndian.Uint64(data[ptr : ptr+8]))
		ptr += 8
		// Read value
		var sk = &bfv.SecretKey{}
		if valueLen > 0 {
			err = sk.UnmarshalBinary(data[ptr : ptr+valueLen])
			ptr += valueLen
			if err != nil {
				return
			}
		}

		// Save entry
		keyMap[network.ServerIdentityID(id)] = sk
	}

	return
}

func (lt *LocalTest) WriteToFile(filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	data, err := lt.MarshalBinary()
	if err != nil {
		return err
	}

	n, err := file.Write(data)
	if err != nil {
		return err
	}
	if n != len(data) {
		err = errors.New("Couldn't write all data")
		return err
	}

	return nil
}
func (lt *LocalTest) ReadFromFile(filename string) error {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return err
	}

	return lt.UnmarshalBinary(data)
}
