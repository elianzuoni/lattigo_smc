package services

import (
	"errors"
	"github.com/ldsec/lattigo/bfv"
	"github.com/ldsec/lattigo/ring"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
	uuid "gopkg.in/satori/go.uuid.v1"
	"lattigo-smc/protocols"
	"lattigo-smc/utils"
	"time"
)

//Service is the service of lattigoSMC - allows to compute the different HE operations
type Service struct {
	*onet.ServiceProcessor
	onet.Roster

	*bfv.Ciphertext
	MasterPublicKey *bfv.PublicKey
	*bfv.SecretKey
	*bfv.PublicKey
	*bfv.EvaluationKey
	Params *bfv.Parameters

	DecryptorSk bfv.Decryptor
	Encoder     bfv.Encoder
	Encryptor   bfv.Encryptor

	pubKeyGenerated     bool
	evalKeyGenerated    bool
	rotKeyGenerated     []bool
	DataBase            map[uuid.UUID]*bfv.Ciphertext
	LocalUUID           map[uuid.UUID]chan uuid.UUID
	Ckgp                *protocols.CollectiveKeyGenerationProtocol
	crpGen              ring.CRPGenerator
	SwitchedCiphertext  map[uuid.UUID]chan bfv.Ciphertext
	SwitchingParameters chan SwitchingParamters
	RotationKey         []bfv.RotationKeys

	SumReplies map[SumQuery]chan uuid.UUID
}

type SwitchingParamters struct {
	bfv.PublicKey
	bfv.Ciphertext
}

type Transaction struct {
	uuid.UUID
	*bfv.Plaintext
	Pending bool
}

func NewLattigoSMCService(c *onet.Context) (onet.Service, error) {
	log.Lvl1(c.ServerIdentity(), "Starting lattigo smc service")

	newLattigo := &Service{
		ServiceProcessor: onet.NewServiceProcessor(c),
		DataBase:         make(map[uuid.UUID]*bfv.Ciphertext),
		LocalUUID:        make(map[uuid.UUID]chan uuid.UUID),
		//LocalData:          make(map[uuid.UUID]*Transaction),
		//PendingTransaction: make(chan *Transaction, 10),
		//KeyReceived:        make(chan bool),
		SwitchedCiphertext:  make(map[uuid.UUID]chan bfv.Ciphertext),
		SwitchingParameters: make(chan SwitchingParamters, 10),
		RotationKey:         make([]bfv.RotationKeys, 3),
		rotKeyGenerated:     make([]bool, 3),

		SumReplies: make(map[SumQuery]chan uuid.UUID),
	}
	//registering the handlers
	if err := newLattigo.RegisterHandler(newLattigo.HandleSendData); err != nil {
		return nil, errors.New("Wrong handler 1:" + err.Error())
	}
	if err := newLattigo.RegisterHandler(newLattigo.HandleSumQuery); err != nil {
		return nil, errors.New("Wrong handler 2:" + err.Error())
	}
	if err := newLattigo.RegisterHandler(newLattigo.HandleMultiplyQuery); err != nil {
		return nil, errors.New("Wrong handler 3:" + err.Error())
	}

	if err := newLattigo.RegisterHandler(newLattigo.HandleSetupQuery); err != nil {
		return nil, errors.New("Wrong handler 5: " + err.Error())
	}

	if err := newLattigo.RegisterHandler(newLattigo.HandlePlaintextQuery); err != nil {
		return nil, errors.New("Wrong handler 7 : " + err.Error())
	}

	if err := newLattigo.RegisterHandler(newLattigo.HandleKeyRequest); err != nil {
		return nil, errors.New("Wrong handler 8 : " + err.Error())
	}

	c.RegisterProcessor(newLattigo, msgTypes.msgQueryData)
	c.RegisterProcessor(newLattigo, msgTypes.msgQuery)
	c.RegisterProcessor(newLattigo, msgTypes.msgSetupRequest)
	c.RegisterProcessor(newLattigo, msgTypes.msgKeyRequest)
	c.RegisterProcessor(newLattigo, msgTypes.msgKeyReply)

	c.RegisterProcessor(newLattigo, msgTypes.msgStoreReply)

	c.RegisterProcessor(newLattigo, msgTypes.msgQueryPlaintext)
	c.RegisterProcessor(newLattigo, msgTypes.msgReplyPlaintext)

	c.RegisterProcessor(newLattigo, msgTypes.msgSumQuery)
	c.RegisterProcessor(newLattigo, msgTypes.msgSumReply)

	return newLattigo, nil
}

func (s *Service) Process(msg *network.Envelope) {
	//Processor interface used to recognize messages between server
	if msg.MsgType.Equal(msgTypes.msgSetupRequest) {
		log.Lvl1(s.ServerIdentity(), "got a setup message! (in process) ")
		tmp := (msg.Msg).(*SetupRequest)
		_, err := s.HandleSetupQuery(tmp)

		if err != nil {
			log.Error(err)
		}
	} else if msg.MsgType.Equal(msgTypes.msgQuery) {
		//query to store data..
		log.Lvl1(s.ServerIdentity(), "got a request to store a cipher")
		tmp := (msg.Msg).(*StoreQuery)
		id := uuid.NewV1()
		s.DataBase[id] = tmp.Ciphertext
		//send an acknowledgement of storing..
		sender := msg.ServerIdentity
		log.Lvl1("Id of cipher : ", tmp.UUID)

		Ack := StoreReply{tmp.UUID, id, true}
		err := s.SendRaw(sender, &Ack)
		if err != nil {
			log.Error("Could not send acknowledgement")
		}
		log.Lvl1("Sent an acknowledgement to  ", sender.String())

	} else if msg.MsgType.Equal(msgTypes.msgQueryData) {

	} else if msg.MsgType.Equal(msgTypes.msgMultiplyQuery) {

	} else if msg.MsgType.Equal(msgTypes.msgSumQuery) {
		log.Lvl1("Got request to sum up ciphertexts")
		tmp := (msg.Msg).(*SumQuery)
		log.Lvl1("Sum :", tmp.UUID, "+", tmp.Other)
		eval := bfv.NewEvaluator(s.Params)
		ct1, ok := s.DataBase[tmp.UUID]
		if !ok {
			log.Error("Ciphertext ", tmp.UUID, " does not exist.")
			return
		}

		ct2, ok := s.DataBase[tmp.Other]
		if !ok {
			log.Error("Ciphertext ", tmp.UUID, " does not exist.")
			return
		}
		id := uuid.NewV1()
		s.DataBase[id] = eval.AddNew(ct1, ct2)
		reply := SumReply{id, *tmp}
		err := s.SendRaw(msg.ServerIdentity, &reply)
		if err != nil {
			log.Error("Could not reply to the server ", err)
		}

	} else if msg.MsgType.Equal(msgTypes.msgSumReply) {
		log.Lvl1("Got message for sum reply")
		tmp := (msg.Msg).(*SumReply)
		s.SumReplies[tmp.SumQuery] <- tmp.UUID
	} else if msg.MsgType.Equal(msgTypes.msgStoreReply) {
		log.Lvl1("Got a store reply")
		tmp := (msg.Msg).(*StoreReply)
		log.Lvl1("ID Local , ", tmp.Local, "ID Remote: ", tmp.Remote, "Done :", tmp.Done)
		//Update the local values.
		s.LocalUUID[tmp.Local] = make(chan uuid.UUID, 1)
		s.LocalUUID[tmp.Local] <- tmp.Remote
		log.Lvl1("Updated value of the ciphertext. ")

	} else if msg.MsgType.Equal(msgTypes.msgKeyRequest) {
		log.Lvl1("Got a key request")
		reply := KeyReply{}
		tmp := (msg.Msg).(*KeyRequest)
		if tmp.PublicKey && s.pubKeyGenerated {
			reply.PublicKey = *bfv.NewPublicKey(s.Params)
			reply.PublicKey.Set(s.MasterPublicKey.Get())
		}
		//if tmp.EvaluationKey && s.evalKeyGenerated{
		//	reply.EvaluationKey = *s.EvaluationKey
		//	reply.Flags |= 2
		//
		//}
		//if tmp.RotationKey{
		//
		//	reply.Flags |= 4
		//}

		//Send the result.
		err := s.SendRaw(msg.ServerIdentity, &reply)
		if err != nil {
			log.Error("Could not send reply : ", err)
		}

	} else if msg.MsgType.Equal(msgTypes.msgKeyReply) {
		log.Lvl1("Got a key reply")
		tmp := (msg.Msg).(*KeyReply)
		if tmp.PublicKey.Get()[0] != nil {
			s.MasterPublicKey = &tmp.PublicKey
		}
		//if tmp.Flags & 2 > 0 {
		//	s.EvaluationKey = &tmp.EvaluationKey
		//}
		//if tmp.Flags & 4 > 0 {
		//	//todo
		//}

		log.Lvl1("Got the public keys !")

	} else if msg.MsgType.Equal(msgTypes.msgReplyPlaintext) {
		tmp := (msg.Msg).(*ReplyPlaintext)
		log.Lvl1("Got a ciphertext switched with UUID : ", tmp.UUID)

		s.SwitchedCiphertext[tmp.UUID] = make(chan bfv.Ciphertext, 1)
		s.SwitchedCiphertext[tmp.UUID] <- *tmp.Ciphertext
	} else if msg.MsgType.Equal(msgTypes.msgQueryPlaintext) {
		log.Lvl1("Got a query for ciphertext switching ")
		//it comes from either the initiator or the root.
		tree := s.Roster.GenerateBinaryTree()
		query := (msg.Msg).(*QueryPlaintext)

		if s.ServerIdentity().Equal(tree.Root.ServerIdentity) {
			//The root has to propagate to all members the ciphertext and the public key...
			//Get the ciphertext.
			cipher := s.DataBase[query.UUID]
			query.Ciphertext = cipher
			//Send to all

			err := utils.SendISMOthers(s.ServiceProcessor, &s.Roster, query)
			if err != nil {
				return
			}
			//Start the key switch
			params := SwitchingParamters{
				PublicKey:  *query.PublicKey,
				Ciphertext: *query.Ciphertext,
			}
			s.SwitchingParameters <- params

			reply, err := s.switchKeys(tree, query.UUID)
			if err != nil {
				log.Error("Could not switch key : ", err)
			}
			log.Lvl1("Finished ciphertext switching. sending result to the querier ! ")
			//reply to the origin of the queries
			err = s.SendRaw(msg.ServerIdentity, reply)
			if err != nil {
				log.Error("Could not send reply to the server :", err)
			}
		} else {
			params := SwitchingParamters{
				PublicKey:  *query.PublicKey,
				Ciphertext: *query.Ciphertext,
			}
			s.SwitchingParameters <- params
		}
	} else {
		log.Error("Unknown message type :", msg.MsgType)
	}

}

//Protocol handlers

func (s *Service) NewProtocol(tn *onet.TreeNodeInstance, conf *onet.GenericConfig) (onet.ProtocolInstance, error) {
	err := tn.SetConfig(conf)
	if err != nil {
		return nil, err
	}
	var protocol onet.ProtocolInstance
	switch tn.ProtocolName() {
	case protocols.CollectiveKeyGenerationProtocolName:
		log.Lvl1(s.ServerIdentity(), ": New protocol ckgp")

		protocol, err = protocols.NewCollectiveKeyGeneration(tn)
		if err != nil {
			return nil, err
		}
		ckgp := protocol.(*protocols.CollectiveKeyGenerationProtocol)

		//init
		crp := s.crpGen.ClockNew()
		err = ckgp.Init(s.Params, s.SecretKey, crp)

		if !tn.IsRoot() {
			go func() {

				log.Lvl1(s.ServerIdentity(), "Waiting for the protocol to be finished...(NewProtocol)")
				ckgp.Wait()
				log.Lvl1(tn.ServerIdentity(), " : done with collective key gen ! ")

				s.SecretKey = ckgp.Sk
				s.DecryptorSk = bfv.NewDecryptor(s.Params, s.SecretKey)
				s.Encoder = bfv.NewEncoder(s.Params)
				s.PublicKey = bfv.NewKeyGenerator(s.Params).GenPublicKey(s.SecretKey)
				s.pubKeyGenerated = true
			}()

		}
	case protocols.CollectiveKeySwitchingProtocolName:
		log.Lvl1(s.ServerIdentity(), ": New protocol cksp")

	case protocols.CollectivePublicKeySwitchingProtocolName:
		log.Lvl1(s.ServerIdentity(), ": New protocol cpksp")
		protocol, err = protocols.NewCollectivePublicKeySwitching(tn)
		if err != nil {
			return nil, err
		}
		pcks := protocol.(*protocols.CollectivePublicKeySwitchingProtocol)
		var publickey bfv.PublicKey
		var ciphertext *bfv.Ciphertext
		sp := <-s.SwitchingParameters
		publickey = sp.PublicKey
		ciphertext = &sp.Ciphertext
		err = pcks.Init(*s.Params, publickey, *s.SecretKey, ciphertext)
		if err != nil {
			return nil, err
		}

	case protocols.RelinearizationKeyProtocolName:
		log.Lvl1(s.ServerIdentity(), ": New protocol rlkp")
		protocol, err = protocols.NewRelinearizationKey(tn)
		if err != nil {
			return nil, err
		}
		rkp := (protocol).(*protocols.RelinearizationKeyProtocol)
		modulus := s.Params.Moduli.Qi
		crp := make([]*ring.Poly, len(modulus))
		for j := 0; j < len(modulus); j++ {
			crp[j] = s.crpGen.ClockNew()
		}
		err = rkp.Init(*s.Params, *s.SecretKey, crp)
		if err != nil {
			log.Error("Error while generating Relin key : ", err)
		}

		if !tn.IsRoot() {
			go func() {

				log.Lvl1(s.ServerIdentity(), "Waiting for the protocol to be finished...(Relin Protocol)")
				rkp.Wait()
				log.Lvl1(tn.ServerIdentity(), " : done with collective relinkey gen ! ")

				s.evalKeyGenerated = true
			}()

		}
	case protocols.RotationProtocolName:
		protocol, err = protocols.NewRotationKey(tn)
		if err != nil {
			log.Error("Could not start rotation :", err)

		}
		rotkey := (protocol).(*protocols.RotationKeyProtocol)
		modulus := s.Params.Moduli.Qi
		crp := make([]*ring.Poly, len(modulus))
		for j := 0; j < len(modulus); j++ {
			crp[j] = s.crpGen.ClockNew()
		}
		var rotIdx int
		var K uint64
		err = rotkey.Init(s.Params, *s.SecretKey, bfv.Rotation(rotIdx), K, crp)
		if err != nil {
			log.Error("Could not start rotation : ", err)

		}

		if !tn.IsRoot() {
			go func() {
				rotkey.Wait()
				s.rotKeyGenerated[rotIdx] = true
			}()
		}
	}

	return protocol, nil
}

func (s *Service) HandlePlaintextQuery(query *QueryPlaintext) (network.Message, error) {
	//Initiate the CKS
	log.Lvl1(s.ServerIdentity(), "got request for plaintext of id : ", query.UUID)
	tree := s.GenerateBinaryTree()

	//From the client Send it to all the other peers so they can initate the PCKS
	query.PublicKey = bfv.NewPublicKey(s.Params)
	query.PublicKey.Set(s.PublicKey.Get())

	err := s.SendRaw(tree.Root.ServerIdentity, query)

	if err != nil {
		log.Error("Could not send the initation message to the root.")
		return nil, err
	}

	//Wait for CKS to complete
	log.Lvl1("Waiting for ciphertext UUID :", query.UUID)
	for {
		select {
		case cipher := <-s.SwitchedCiphertext[query.UUID]:
			log.Lvl1("Got my ciphertext : ", query.UUID)
			plain := s.DecryptorSk.DecryptNew(&cipher)
			//todo ask : when decoding the cipher text the values are not what is expected.
			data64 := s.Encoder.DecodeUint(plain)
			bytes, err := utils.Uint64ToBytes(data64, true)
			if err != nil {
				log.Error("Could not retrieve byte array : ", err)
			}
			response := &PlaintextReply{UUID: query.UUID, Data: bytes}

			return response, nil
		case <-time.After(time.Second):
			log.Lvl1("Still waiting on ciphertext :", query.UUID)
			break
		}

	}

}

/*************UNUSED FOR NOW ******************/
func (s *Service) StartProtocol(name string) (onet.ProtocolInstance, error) {
	log.Lvl1(s.ServerIdentity(), ": starts protocol :", name)
	tree := s.GenerateBigNaryTree(2, len(s.Roster.List))
	tni := s.NewTreeNodeInstance(tree, tree.Root, name)
	var conf onet.GenericConfig //todo what is the config ?
	protocol, err := s.NewProtocol(tni, &conf)
	if err != nil {
		return nil, errors.New("Error runnning " + name + ": " + err.Error())
	}
	err = s.RegisterProtocolInstance(protocol)
	if err != nil {
		return nil, err
	}
	go func(protoname string) {
		err := protocol.Dispatch()
		if err != nil {
			log.Error("Error in dispatch : ", err)
		}
	}(name)

	go func(protoname string) {
		err := protocol.Start()
		if err != nil {
			log.Error("Error on start :", err)
		}
	}(name)

	return protocol, nil
}
