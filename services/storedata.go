package services

import (
	"errors"
	"github.com/ldsec/lattigo/bfv"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
	uuid "gopkg.in/satori/go.uuid.v1"
	"lattigo-smc/utils"
	"time"
)

//HandleSendData is called by the service when the client makes a request to write some data.
func (s *Service) HandleSendData(query *QueryData) (network.Message, error) {
	log.Lvl1(s.ServerIdentity(), " received query data ")

	data := query.Data

	tree := query.Roster.GenerateBinaryTree()

	if !s.pubKeyGenerated {
		//here we can not yet do the answer
		return nil, errors.New("Key has not yet been generated.")
	}
	if s.MasterPublicKey == nil {
		log.Lvl1("Master public key not available")
		return &ServiceState{
			Id:      uuid.UUID{},
			Pending: true,
		}, nil

	}

	encoder := bfv.NewEncoder(s.Params)
	coeffs, err := utils.BytesToUint64(data)
	if err != nil {
		return nil, err
	}
	pt := bfv.NewPlaintext(s.Params)
	encoder.EncodeUint(coeffs, pt)

	id := uuid.NewV1()
	//Send it to the server
	encryptorPk := bfv.NewEncryptorFromPk(s.Params, s.MasterPublicKey)
	cipher := encryptorPk.EncryptNew(pt)
	err = s.SendRaw(tree.Root.ServerIdentity, &StoreQuery{*cipher, id})
	if err != nil {
		log.Error("could not send cipher to the root. ")
	}

	log.Lvl1("Waiting for id to be updated!")
	for {
		select {
		case remoteID := <-s.LocalUUID[id]:
			log.Lvl1("Value was updated")
			return &ServiceState{remoteID, true}, nil

		case <-time.After(1 * time.Second):
			break
		}
	}

}

//HandleKeyRequest handler for a client for the requests for the keys.
func (s *Service) HandleKeyRequest(request *KeyRequest) (network.Message, error) {
	tree := s.Roster.GenerateBinaryTree()
	log.Lvl1("Querying for a key :", request)
	err := s.SendRaw(tree.Root.ServerIdentity, request)
	if err != nil {
		return nil, err
	}
	return &SetupReply{Done: 1}, nil
}
