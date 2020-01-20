package test

//checking if the marshalling works.
//func TestMarshallingSwitchingParameters(t *testing.T) {
//	params := bfv.DefaultParams[0]
//	PlainText := bfv.NewPlaintext(params)
//	encoder := bfv.NewEncoder(params)
//
//	encoder.EncodeUint(ring.NewRandomPlaintextCoeffs(), PlainText)
//
//	//TODO check degree
//	cipher := bfv.NewCiphertextRandom(params, 4)
//	sp := protocols.SwitchingParameters{
//		Params:       *bfv.DefaultParams[0],
//		SkInputHash:  "123456",
//		SkOutputHash: "hjkdsaufdsijfsoidajfoidscnmijdsahfiudsojfdsaihfiudsafdsij",
//		Ciphertext:   *cipher,
//	}
//
//	data, err := sp.MarshalBinary()
//
//	sp1 := new(protocols.SwitchingParameters)
//	err = sp1.UnmarshalBinary(data)
//
//	if err != nil {
//		log.Error("Error in unmarshalling : ", err)
//		t.Fail()
//	}
//
//	//compare both...
//	if sp1.SkOutputHash != sp.SkOutputHash {
//		log.Print("Differnet output hashes")
//		t.Fail()
//
//	}
//	if sp1.SkInputHash != sp.SkInputHash {
//		log.Print("Different input hashes")
//		t.Fail()
//	}
//
//	if !sp1.Params.Equals(&sp.Params) {
//		log.Print("Different parameters")
//		t.Fail()
//	}
//	//TODO check cipher texts.
//	return
//}

//func TestCiphertextMarshal(t *testing.T) {
//	receiver := new(bfv.Ciphertext)
//	params := bfv.DefaultParams[0]
//	cipher := bfv.NewCiphertextRandom(params, 1)
//	data, _ := cipher.MarshalBinary()
//
//	_ = receiver.UnmarshalBinary(data)
//	for i := 0; uint64(i) < receiver.Degree()+1; i++ {
//		err := utils.ComparePolys(*receiver.Value()[0], *cipher.Value()[0])
//		if err != nil {
//			fmt.Print(err)
//			t.Fail()
//			return
//		}
//	}
//
//	fmt.Print("Success")
//
//}
//
//func TestCRPMarshal(t *testing.T) {
//
//}
