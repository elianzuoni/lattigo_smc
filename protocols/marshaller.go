//Marshalling of structures - was used to send the parameters to the nodes
// Keeping it in case it can be used later.

package protocols

import (
	"errors"
	"github.com/ldsec/lattigo/bfv"
	"github.com/ldsec/lattigo/ring"
	"strings"
)

//MarshalBinary creates a data array from the switching parameters sp
func (sp SwitchingParameters) MarshalBinary() (data []byte, err error) {
	var buffer strings.Builder

	data = make([]byte, 0)
	param, err := sp.Params.MarshalBinary()
	lenParam := len(param)
	data = append(data, byte(lenParam))
	buffer.WriteByte(byte(lenParam))
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

//UnmarshalBinary loads the data into the switching parameters.
func (sp *SwitchingParameters) UnmarshalBinary(data []byte) (err error) {
	ptr := data[0]
	byteParam := data[1 : ptr+1]
	err = sp.Params.UnmarshalBinary(byteParam)

	//then get the hashes..
	ptr++
	lenHashes := data[ptr]
	hashes := data[ptr+1 : ptr+lenHashes+1]
	ptr += lenHashes + 1
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

//MarshalBinary creates a data array from the CRP
func (crp *CRP) MarshalBinary() ([]byte, error) {
	if len(crp.A) == 0 || len(crp.A[0]) == 0 {
		return []byte{}, nil
	}
	//compute the total data length.
	ringLen := crp.A[0][0].GetDataLen(true)
	length := uint64(len(crp.A)*len(crp.A[0])) * ringLen
	data := make([]byte, length+2)
	data[0] = uint8(len(crp.A))
	data[1] = uint8(len(crp.A[0]))
	ptr := uint64(2)
	for _, xs := range crp.A {
		for _, x := range xs {
			cnt, err := x.WriteTo(data[ptr : ptr+ringLen])
			if err != nil {
				return []byte{}, errors.New("Could not write the crp")
			}
			ptr += cnt
		}
	}

	return data, nil
}

//UnmarshalBinary creates the crp object from the data array.
func (crp *CRP) UnmarshalBinary(data []byte) error {
	outerLen := data[0]
	innerLen := data[1]
	lenRing := uint64((len(data) - 2) / int(outerLen) / int(innerLen))
	//allocate if necessary.
	if crp.A == nil {
		crp.A = make([][]*ring.Poly, outerLen)
		for i := 0; i < int(outerLen); i++ {
			crp.A[i] = make([]*ring.Poly, innerLen)
		}
	}

	ptr := uint64(2)

	for i := 0; i < int(outerLen); i++ {
		for j := 0; j < int(innerLen); j++ {
			crp.A[i][j] = new(ring.Poly)
			err := crp.A[i][j].UnmarshalBinary(data[ptr : ptr+lenRing])
			if err != nil {
				return err
			}

			ptr += lenRing
		}
	}

	return nil

}
