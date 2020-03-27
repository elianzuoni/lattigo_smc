package service

import (
	"github.com/ldsec/lattigo/bfv"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
	uuid "gopkg.in/satori/go.uuid.v1"
	"lattigo-smc/protocols"
	"lattigo-smc/utils"
	"time"
)

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

func (s *Service) processPlaintextQuery(msg *network.Envelope) {
	//it comes from either the initiator or the root.
	tree := s.Roster.GenerateBinaryTree()
	query := (msg.Msg).(*QueryPlaintext)
	log.Lvl1("Got a query for ciphertext switching : ", query.UUID)
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
		params := SwitchingParameters{
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
		params := SwitchingParameters{
			PublicKey:  *query.PublicKey,
			Ciphertext: *query.Ciphertext,
		}
		s.SwitchingParameters <- params
	}
	return
}

func (s *Service) processPlaintextReply(msg *network.Envelope) {
	tmp := (msg.Msg).(*ReplyPlaintext)
	log.Lvl1("Got a ciphertext switched with UUID : ", tmp.UUID)
	s.SwitchedCiphertext[tmp.UUID] = make(chan bfv.Ciphertext, 1)
	s.SwitchedCiphertext[tmp.UUID] <- *tmp.Ciphertext
}

func (s *Service) switchKeys(tree *onet.Tree, id uuid.UUID) (*ReplyPlaintext, error) {
	log.Lvl1(s.ServerIdentity(), " Switching keys")
	tni := s.NewTreeNodeInstance(tree, tree.Root, protocols.CollectivePublicKeySwitchingProtocolName)
	protocol, err := s.NewProtocol(tni, nil)
	if err != nil {
		return nil, err
	}

	err = s.RegisterProtocolInstance(protocol)
	if err != nil {
		return nil, err
	}

	pks := protocol.(*protocols.CollectivePublicKeySwitchingProtocol)
	<-time.After(1 * time.Second)
	err = pks.Start()
	if err != nil {
		log.ErrFatal(err, "Could not start collective public key switching")
	}
	go pks.Dispatch()
	log.Lvl1(pks.ServerIdentity(), "waiting for protocol to be finished ")
	pks.Wait()

	//Send the ciphertext to the original asker.
	reply := ReplyPlaintext{
		UUID:       id,
		Ciphertext: &pks.CiphertextOut,
	}
	return &reply, err
}
