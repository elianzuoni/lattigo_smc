package protocols

import (
	"errors"
	"github.com/ldsec/lattigo/bfv"
	"github.com/ldsec/lattigo/ring"
	"strings"
)

func (sp SwitchingParameters) MarshalBinary() (data []byte, err error) {
	var buffer strings.Builder

	data = make([]byte, 0)
	param, err := sp.Params.MarshalBinary()
	len_param := len(param)
	data = append(data, byte(len_param))
	buffer.WriteByte(byte(len_param))
	buffer.Write(param)
	//add the strings...
	hashes := []byte(sp.SkInputHash + "," + sp.SkOutputHash)
	buffer.WriteByte(byte(len(hashes)))
	buffer.Write(hashes)

	//add the cipher..
	cipher, err := sp.Ciphertext.MarshalBinary()

	buffer.Write(cipher)

	return []byte(buffer.String()), nil

}

func (sp *SwitchingParameters) UnmarshalBinary(data []byte) (err error) {
	ptr := data[0]
	byte_param := data[1 : ptr+1]
	err = sp.Params.UnmarshalBinary(byte_param)

	//then get the hashes..
	ptr++
	len_hashes := data[ptr]
	hashes := data[ptr+1 : ptr+len_hashes+1]
	ptr += len_hashes + 1
	xs := strings.Split(string(hashes), ",")
	if len(xs) != 2 {
		return errors.New("Error on hashes")

	}
	sp.SkInputHash = xs[0]
	sp.SkOutputHash = xs[1]
	//finally the cipher text..
	//bfvCtx, err := bfv.NewBfvContextWithParam(&sp.Params)

	//len_cipher := data[ptr]
	//ptr++
	sp.Ciphertext = *new(bfv.Ciphertext)
	err = sp.Ciphertext.UnmarshalBinary(data[ptr:])
	if err != nil {
		return err
	}
	return nil

}

//TODO test crp marshalling

func (crp *CRP) MarshalBinary()([]byte,error){
	if len(crp.a) == 0 || len(crp.a[0]) == 0 {
		return []byte{},nil
	}
	//compute the total data length.
	ringLen := crp.a[0][0].GetDataLen(true)
	length := uint64(len(crp.a) * len(crp.a[0])) * ringLen
	data := make([]byte,length+2)
	data[0] = uint8(len(crp.a))
	data[1] = uint8(len(crp.a[0]))
	ptr := uint64(2)
	for _, xs := range crp.a{
		for _, x := range xs{
			cnt , err := x.WriteTo(data[ptr:ptr+ringLen])
			if err != nil{
				return []byte{},errors.New("Could not write the crp")
			}
			ptr+=cnt
		}
	}

	return data, nil
}

func (crp *CRP) UnmarshalBinary(data []byte)error{
	outerLen := data[0]
	innerLen := data[1]
	lenRing := uint64((len(data)-2)/int(outerLen)/int(innerLen))
	//allocate if necessary.
	if crp.a == nil{
		crp.a = make([][]*ring.Poly,outerLen)
		for i := 0 ; i < int(outerLen); i++{
			crp.a[i] = make([]*ring.Poly,innerLen)
		}
	}

	ptr := uint64(2)

	for i := 0 ; i < int(outerLen); i++{
		for j := 0 ; j < int(innerLen) ; j ++{
			crp.a[i][j] = new(ring.Poly)
			err := crp.a[i][j].UnmarshalBinary(data[ptr:ptr+lenRing])
			if err != nil{
				return err
			}

			ptr += lenRing
		}
	}

	return nil

}