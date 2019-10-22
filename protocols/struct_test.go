package protocols

import (
	"fmt"
	"github.com/ldsec/lattigo/bfv"
	"go.dedis.ch/onet/v3/log"
	"lattigo-smc/utils"
	"testing"
)

//checking if the marshalling works.
func TestMarshallingSwitchingParameters(t *testing.T) {
	bfvCtx, err := bfv.NewBfvContextWithParam(&bfv.DefaultParams[0])
	PlainText := bfvCtx.NewPlaintext()
	encoder, err := bfvCtx.NewBatchEncoder()
	err = encoder.EncodeUint(bfvCtx.NewRandomPlaintextCoeffs(), PlainText)
	if err != nil {
		log.Print("Could not encode plaintext : ", err)
		t.Fail()
	}
	//TODO check degree
	cipher := bfvCtx.NewRandomCiphertext(4)
	sp := SwitchingParameters{
		Params:       bfv.DefaultParams[0],
		SkInputHash:  "123456",
		SkOutputHash: "hjkdsaufdsijfsoidajfoidscnmijdsahfiudsojfdsaihfiudsafdsij",
		Ciphertext:   *cipher,
	}

	data, err := sp.MarshalBinary()

	sp1 := new(SwitchingParameters)
	err = sp1.UnmarshalBinary(data)

	if err != nil {
		log.Error("Error in unmarshalling : " , err )
		t.Fail()
	}

	//compare both...
	if sp1.SkOutputHash != sp.SkOutputHash {
		log.Print("Differnet output hashes")
		t.Fail()

	}
	if sp1.SkInputHash != sp.SkInputHash {
		log.Print("Different input hashes")
		t.Fail()
	}

	if !sp1.Params.Equals(&sp.Params) {
		log.Print("Different parameters")
		t.Fail()
	}
	//TODO check cipher texts.
	return
}

func TestCiphertextMarshal(t *testing.T) {
	receiver := new(bfv.Ciphertext)
	ctx, _ := bfv.NewBfvContextWithParam(&bfv.DefaultParams[0])
	cipher := ctx.NewRandomCiphertext(1)
	data, _ := cipher.MarshalBinary()

	_ = receiver.UnmarshalBinary(data)
	for i := 0; uint64(i) < receiver.Degree()+1; i++ {
		err := utils.ComparePolys(*receiver.Value()[0], *cipher.Value()[0])
		if err != nil {
			fmt.Print(err)
			t.Fail()
			return
		}
	}

	fmt.Print("Success")

}
