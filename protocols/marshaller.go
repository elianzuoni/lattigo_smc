//Marshalling of structures - was used to send the parameters to the nodes
// Keeping it in case it can be used later.

package protocols

import (
	"errors"
	"github.com/ldsec/lattigo/ring"
)

//MarshalBinary creates a data array from the CRP
func (crp *CRP) MarshalBinary() ([]byte, error) {
	if len(crp.A) == 0 {
		return []byte{}, nil
	}
	//compute the total data length.
	ringLen := crp.A[0].GetDataLen(true)
	length := uint64(len(crp.A)) * ringLen
	data := make([]byte, length+2)
	data[0] = uint8(len(crp.A))
	ptr := uint64(1)
	for _, x := range crp.A {
		cnt, err := x.WriteTo(data[ptr : ptr+ringLen])
		if err != nil {
			return []byte{}, errors.New("Could not write the crp")
		}
		ptr += cnt
	}

	return data, nil
}

//UnmarshalBinary creates the crp object from the data array.
func (crp *CRP) UnmarshalBinary(data []byte) error {
	outerLen := data[0]
	lenRing := uint64((len(data) - 1) / int(outerLen))
	//allocate if necessary.
	if crp.A == nil {
		crp.A = make([]*ring.Poly, outerLen)

	}

	ptr := uint64(2)

	for i := 0; i < int(outerLen); i++ {
		crp.A[i] = new(ring.Poly)
		err := crp.A[i].UnmarshalBinary(data[ptr : ptr+lenRing])
		if err != nil {
			return err
		}

		ptr += lenRing
	}

	return nil

}
