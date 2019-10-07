package protocols

import (
	"errors"
	"github.com/ldsec/lattigo/bfv"
	"github.com/ldsec/lattigo/ring"
	"go.dedis.ch/onet/v3"
	"strings"
)



type KeyRing struct {
	//Ideally use maybe this in the future to have a single structure.. but maybe it will get too big ~ check later
	//everything needed for the keys.
	//*dbfv.CKG
	//*dbfv.EkgProtocol
	//*dbfv.PCKS

	sk *bfv.SecretKey
	rlkEphemSk *ring.Poly
	input []uint64
}



type CollectiveKeyGenerationProtocol struct {
	*onet.TreeNodeInstance

	Params bfv.Parameters

	ChannelParams          chan StructParameters
	ChannelPublicKeyShares chan StructPublicKeyShare
	ChannelPublicKey       chan StructPublicKey
}


type CollectiveKeySwitchingProtocol struct{
	*onet.TreeNodeInstance

	Params SwitchingParameters

	ChannelParams chan StructSwitchParameters
	ChannelCiphertext chan StructCiphertext
	ChannelCKSShare chan StructCKSShare
}

type StructCKSShare struct{
	*onet.TreeNode
	ring.Poly
}


type SwitchingParameters struct{
	Params bfv.Parameters
	//also need skIn, skOut
	SkInputHash string
	SkOutputHash string
	bfv.Ciphertext
}

//Quick experience to marshal the swiching parameters. - works TODO need to clean up
func (sp *SwitchingParameters)MarshalBinary() (data []byte, err error){
	var buffer strings.Builder

	data = make([]byte,0)
	param ,err := sp.Params.MarshalBinary()
	len_param := len(param)
	data = append(data, byte(len_param))
	buffer.WriteByte(byte(len_param))
	buffer.Write(param)
	//add the strings...
	hashes := []byte(sp.SkInputHash+","+sp.SkOutputHash)
	buffer.WriteByte(byte(len(hashes)))
	buffer.Write(hashes)

	//add the cipher..
	cipher, err := sp.Ciphertext.MarshalBinary()

	buffer.Write(cipher)

	return []byte(buffer.String()), nil

}


func (sp *SwitchingParameters)UnmarshalBinary(data []byte) (err error){
	ptr := data[0]
	byte_param := data[1:ptr+1]
	err = sp.Params.UnmarshalBinary(byte_param)

	//then get the hashes..
	ptr++
	len_hashes := data[ptr]
	hashes := data[ptr+1:ptr + len_hashes+1]
	ptr += len_hashes + 1
	xs := strings.Split(string(hashes),",")
	if len(xs) != 2{
		return errors.New("Error on hashes")

	}
	sp.SkInputHash = xs[0]
	sp.SkOutputHash = xs[1]
	//finally the cipher text..
	bfvCtx,err := bfv.NewBfvContextWithParam(&sp.Params)

	//len_cipher := data[ptr]
	//ptr++
	sp.Ciphertext = *bfvCtx.NewCiphertext(1)
	err = sp.Ciphertext.UnmarshalBinary(data[ptr:])
	if err !=nil{
		return err
	}
	return nil


}


type StructSwitchParameters struct{
	*onet.TreeNode
	SwitchingParameters
}

type StructCiphertext struct{
	*onet.TreeNode
	bfv.Ciphertext
}


type CollectiveKeyShare struct {
	ring.Poly
}


type StructParameters struct {
	*onet.TreeNode
	Params bfv.Parameters
}



type StructPublicKeyShare struct {
	*onet.TreeNode
	CollectiveKeyShare
}

type StructPublicKey struct {
	*onet.TreeNode
	ring.Poly
}




