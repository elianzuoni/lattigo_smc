package examples

func check(err error) {
	if err != nil {
		panic(err)
	}
}

func Main() {
/*
	N := 4

	type party struct {
		*dbfv.CKGProtocol
		*dbfv.RKGProtocol
		*dbfv.PCKSProtocol

		sk *bfv.SecretKey
		rlkEphemSk *ring.Poly
		input []uint64
	}

	params := bfv.DefaultParams[3]
	params.T = 65537
	bfvctx,err := bfv.NewBfvContextWithParam(&params)
	check(err)

	bitDecomp := uint64(60)
	modlen := len(bfvctx.ContextQ().Modulus)
	bitLog := uint64((60 + (60 % bitDecomp)) / bitDecomp)


	crsGen, _ := dbfv.NewCRPGenerator([]byte{'l','a', 't', 't', 'i', 'g', 'o'}, bfvctx.ContextQ())
	//crs := crsGen.Clock()
	crp := make([][]*ring.Poly, modlen)
	for i := 0; i < modlen; i++ {
		crp[i] = make([]*ring.Poly, bitLog)
		for j := uint64(0); j < bitLog; j++ {
			crp[i][j] = crsGen.Clock()
		}
	}
	//TODO p = 0.0 here
	p:= 1.0/3
	tsk,tpk, err := bfvctx.NewKeyGenerator().NewKeyPair(p)
	check(err)
	colSk := &bfv.SecretKey{}
	colSk.Set(bfvctx.ContextQ().NewPoly())

	P := make([]*party, N, N)
	for i := range P {
		pi :=  &party{}
		P[i] = pi
		//TODO p = 0.0 here

		pi.sk,err = bfvctx.NewKeyGenerator().NewSecretKey(0.0)
		if err != nil {
			log.Printf("error : %v \n", err)
			return
		}
		pi.input = []uint64{0,1,0,1,0,1,0,0}
		pi.CKGProtocol = dbfv.NewCKGProtocol(bfvctx)
		pi.RKGProtocol = dbfv.NewEkgProtocol(bfvctx, bitDecomp)
		pi.PCKSProtocol = dbfv.NewPCKSProtocol(bfvctx, params.Sigma)

		bfvctx.ContextQ().Add(colSk.Get(), pi.sk.Get(), colSk.Get()) //TODO: doc says "return"
	}

	fmt.Println("> CKG Phase")
	cpkShares := make([]*ring.Poly, N, N)
	for i, pi := range P {

		err = pi.GenShare(pi.sk.Get())
		check(err)
		cpkShares[i] = pi.GetShare()
	}
	_ = P[0].AggregateShares(cpkShares) // TODO: interface not ideal
	pk, err := P[0].Finalize()
	check(err)
	encryptor, err := bfvctx.NewEncryptor(pk,tsk)


	fmt.Println("> RKG Phase")
	samples := make([][][]*ring.Poly, N) // TODO: type for [][]*ring.Poly ?
	for i, pi := range P {
		samples[i] = make([][]*ring.Poly, modlen)
		//TODO p = 0.0 here

		pi.rlkEphemSk ,err = pi.NewEphemeralKey(0.0)
		samples[i] = pi.GenSamples(pi.rlkEphemSk, pi.sk.Get(), crp)
	}
	aggregatedSamples := make([][][][2]*ring.Poly, N) // TODO: term aggreg not ideal
	for i, pi := range P {
		aggregatedSamples[i] = pi.EkgProtocol.Aggregate(pi.sk.Get(), samples, crp) // TODO: interface not ideal for intermediary aggreg
	}
	sum := P[0].Sum(aggregatedSamples)
	keySwitched := make([][][]*ring.Poly, N)
	for i, pi := range P {
		keySwitched[i] = pi.EkgProtocol.KeySwitch(pi.rlkEphemSk, pi.sk.Get(), sum)
	}
	rlk := new(bfv.EvaluationKey)
	//TODO take the version from master branch later..
	//bfv.KeyGenerator.NewRelinKey([][][][2]*ring.Poly{P[0].ComputeEVK(keySwitched, sum)}, bitDecomp,1,1)
	//rlk.NewRelinKey([][][][2]*ring.Poly{P[0].ComputeEVK(keySwitched, sum)}, bitDecomp)
	check(err)


	// Pre-loading memory
	fmt.Println("> Memory alloc Phase")
	encInputs := make([]*bfv.Ciphertext, N, N)
	for i := range encInputs {
		encInputs[i] = bfvctx.NewCiphertext(1)
	}
	encLvl4 := make([]*bfv.Ciphertext, N/2, N/2)
	for i := range encLvl4 {
		encLvl4[i] = bfvctx.NewCiphertext(2)
	}
	encRes := bfvctx.NewCiphertext(2)
	evaluator, err := bfvctx.NewEvaluator()
	check(err)

	fmt.Println("> Encrypt Phase")
	encoder := bfvctx.NewBatchEncoder()
	pt := bfvctx.NewPlaintext()
	for i, pi := range P {
		err = encoder.EncodeUint(pi.input, pt)
		check(err)

		err = encryptor.EncryptFromPk(pt, encInputs[i])
		check(err)
	}

	fmt.Println("> Eval Phase")
	err = evaluator.Mul(encInputs[0], encInputs[1], encLvl4[0])
	check(err)
	err = evaluator.Mul(encInputs[2], encInputs[3], encLvl1[1])
	check(err)
	err = evaluator.Relinearize(encLvl1[0], rlk, encLvl1[0])
	check(err)
	err = evaluator.Relinearize(encLvl1[1], rlk, encLvl1[1])
	check(err)
	err = evaluator.Mul(encLvl1[0], encLvl1[1], encRes)
	check(err)
	err = evaluator.Relinearize(encRes, rlk, encRes)
	check(err)


	fmt.Println("> PCKS Phase")
	cksShares := make([][2]*ring.Poly, N)
	for i, pi := range P {
		cksShares[i] = pi.PCKS.KeySwitch(encRes.Value()[1])
	}
	P[0].PCKS.Aggregate(encRes.Value(), cksShares) // TODO: is it ok to call this multiple times ?

	fmt.Println("> Result:")
	decryptor, err := bfvctx.NewDecryptor(tsk)
	check(err)
	ptres, err := decryptor.DecryptNew(encRes)
	check(err)
	res, err := encoder.DecodeUint(ptres)
	check(err)
	fmt.Printf("%v\n", res[:len(P[0].input)])
*/
}