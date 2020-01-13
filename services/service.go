package services

import (
	"errors"
	"github.com/ldsec/lattigo/bfv"
	"github.com/ldsec/lattigo/ring"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	uuid "gopkg.in/satori/go.uuid.v1"
	"lattigo-smc/protocols"
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

	SumReplies      map[SumQuery]chan uuid.UUID
	MultiplyReplies map[MultiplyQuery]chan uuid.UUID
	RotationReplies map[uuid.UUID]chan uuid.UUID

	RefreshParams chan *bfv.Ciphertext
	RotIdx        int
	K             uint64
}

type SwitchingParamters struct {
	bfv.PublicKey
	bfv.Ciphertext
}

func NewLattigoSMCService(c *onet.Context) (onet.Service, error) {
	log.Lvl1(c.ServerIdentity(), "Starting lattigo smc service")

	newLattigo := &Service{
		ServiceProcessor: onet.NewServiceProcessor(c),
		DataBase:         make(map[uuid.UUID]*bfv.Ciphertext),
		LocalUUID:        make(map[uuid.UUID]chan uuid.UUID),

		SwitchedCiphertext:  make(map[uuid.UUID]chan bfv.Ciphertext),
		SwitchingParameters: make(chan SwitchingParamters, 10),
		RotationKey:         make([]bfv.RotationKeys, 3),
		rotKeyGenerated:     make([]bool, 3),

		SumReplies:      make(map[SumQuery]chan uuid.UUID),
		MultiplyReplies: make(map[MultiplyQuery]chan uuid.UUID),
		RefreshParams:   make(chan *bfv.Ciphertext, 3),
		RotationReplies: make(map[uuid.UUID]chan uuid.UUID),
	}
	//registering the handlers
	e := registerHandlers(newLattigo)
	if e != nil {
		return nil, e
	}
	registerProcessors(c, newLattigo)

	return newLattigo, nil
}

func registerHandlers(newLattigo *Service) error {
	if err := newLattigo.RegisterHandler(newLattigo.HandleSendData); err != nil {
		return errors.New("Wrong handler 1:" + err.Error())
	}
	if err := newLattigo.RegisterHandler(newLattigo.HandleSumQuery); err != nil {
		return errors.New("Wrong handler 2:" + err.Error())
	}
	if err := newLattigo.RegisterHandler(newLattigo.HandleMultiplyQuery); err != nil {
		return errors.New("Wrong handler 3:" + err.Error())
	}
	if err := newLattigo.RegisterHandler(newLattigo.HandleSetupQuery); err != nil {
		return errors.New("Wrong handler 5: " + err.Error())
	}
	if err := newLattigo.RegisterHandler(newLattigo.HandlePlaintextQuery); err != nil {
		return errors.New("Wrong handler 7 : " + err.Error())
	}
	if err := newLattigo.RegisterHandler(newLattigo.HandleKeyRequest); err != nil {
		return errors.New("Wrong handler 8 : " + err.Error())
	}
	if err := newLattigo.RegisterHandler(newLattigo.HandleRelinearizationQuery); err != nil {
		return errors.New("Wrong handler 9 : " + err.Error())
	}
	if err := newLattigo.RegisterHandler(newLattigo.HandleRefreshQuery); err != nil {
		return errors.New("Wrong handler 10 : " + err.Error())
	}
	if err := newLattigo.RegisterHandler(newLattigo.HandleRotationQuery); err != nil {
		return errors.New("Wrong handler 11 : " + err.Error())
	}
	return nil
}

func registerProcessors(c *onet.Context, newLattigo *Service) {
	c.RegisterProcessor(newLattigo, msgTypes.msgSetupRequest)
	c.RegisterProcessor(newLattigo, msgTypes.msgKeyRequest)
	c.RegisterProcessor(newLattigo, msgTypes.msgKeyReply)
	c.RegisterProcessor(newLattigo, msgTypes.msgStoreQuery)
	c.RegisterProcessor(newLattigo, msgTypes.msgStoreReply)
	c.RegisterProcessor(newLattigo, msgTypes.msgQueryPlaintext)
	c.RegisterProcessor(newLattigo, msgTypes.msgReplyPlaintext)
	c.RegisterProcessor(newLattigo, msgTypes.msgSumQuery)
	c.RegisterProcessor(newLattigo, msgTypes.msgSumReply)
	c.RegisterProcessor(newLattigo, msgTypes.msgMultiplyQuery)
	c.RegisterProcessor(newLattigo, msgTypes.msgMultiplyReply)
	c.RegisterProcessor(newLattigo, msgTypes.msgRelinQuery)
	c.RegisterProcessor(newLattigo, msgTypes.msgRefreshQuery)
	c.RegisterProcessor(newLattigo, msgTypes.msgRotationQuery)
	c.RegisterProcessor(newLattigo, msgTypes.msgRotationReply)
}
