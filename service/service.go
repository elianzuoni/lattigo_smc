package service

import (
	"errors"
	"github.com/ldsec/lattigo/bfv"
	"github.com/ldsec/lattigo/ring"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
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
	rotKeyGenerated     bool
	DataBase            map[uuid.UUID]*bfv.Ciphertext
	LocalUUID           map[uuid.UUID]chan uuid.UUID
	Ckgp                *protocols.CollectiveKeyGenerationProtocol
	crpGen              ring.CRPGenerator
	SwitchedCiphertext  map[uuid.UUID]chan bfv.Ciphertext
	SwitchingParameters chan SwitchingParameters
	RotationKey         *bfv.RotationKeys

	SumReplies      map[SumQuery]chan uuid.UUID
	MultiplyReplies map[MultiplyQuery]chan uuid.UUID
	RotationReplies map[uuid.UUID]chan uuid.UUID

	RefreshParams chan *bfv.Ciphertext
	RotIdx        int
	K             uint64
}

func NewLattigoSMCService(c *onet.Context) (onet.Service, error) {
	log.Lvl1(c.ServerIdentity(), "Starting lattigo smc service")

	smcService := &Service{
		ServiceProcessor: onet.NewServiceProcessor(c),
		DataBase:         make(map[uuid.UUID]*bfv.Ciphertext),
		LocalUUID:        make(map[uuid.UUID]chan uuid.UUID),

		SwitchedCiphertext:  make(map[uuid.UUID]chan bfv.Ciphertext),
		SwitchingParameters: make(chan SwitchingParameters, 10),

		SumReplies:      make(map[SumQuery]chan uuid.UUID),
		MultiplyReplies: make(map[MultiplyQuery]chan uuid.UUID),
		RefreshParams:   make(chan *bfv.Ciphertext, 3),
		RotationReplies: make(map[uuid.UUID]chan uuid.UUID),
	}

	// Registers the handlers for client requests.
	e := registerClientQueryHandlers(smcService)
	if e != nil {
		return nil, e
	}
	// Registers the (unique) handler for server's messages.
	registerServerMsgHandler(c, smcService)

	return smcService, nil
}

// Registers in smcService handlers - of the form func(msg interface{})(ret interface{}, err error) -
// for every possible type of client request, implicitly identified by the type of msg.
func registerClientQueryHandlers(smcService *Service) error {
	if err := smcService.RegisterHandler(smcService.HandleStoreQuery); err != nil {
		return errors.New("Couldn't register HandleStoreQuery: " + err.Error())
	}
	if err := smcService.RegisterHandler(smcService.HandleSumQuery); err != nil {
		return errors.New("Couldn't register HandleSumQuery: " + err.Error())
	}
	if err := smcService.RegisterHandler(smcService.HandleMultiplyQuery); err != nil {
		return errors.New("Couldn't register HandleMultiplyQuery: " + err.Error())
	}
	if err := smcService.RegisterHandler(smcService.HandleSetupQuery); err != nil {
		return errors.New("Couldn't register HandleSetupQuery: " + err.Error())
	}
	if err := smcService.RegisterHandler(smcService.HandlePlaintextQuery); err != nil {
		return errors.New("Couldn't register HandlePlaintextQuery: " + err.Error())
	}
	if err := smcService.RegisterHandler(smcService.HandleKeyQuery); err != nil {
		return errors.New("Couldn't register HandleKeyQuery: " + err.Error())
	}
	if err := smcService.RegisterHandler(smcService.HandleRelinearizationQuery); err != nil {
		return errors.New("HandleRelinearizationquery: " + err.Error())
	}
	if err := smcService.RegisterHandler(smcService.HandleRefreshQuery); err != nil {
		return errors.New("Couldn't register HandleRefreshQuery: " + err.Error())
	}
	if err := smcService.RegisterHandler(smcService.HandleRotationQuery); err != nil {
		return errors.New("HandleRotationQuery: " + err.Error())
	}
	return nil
}

// Registers smcService to the underlying onet.Context as a processor for all the possible types of messages
// received by another server (every client request is forwarded to the root, so every query entails some
// server-to-server interaction). Upon reception of one of these messages, the method Process will be invoked.
// TODO: how does onet distinguish the two SumQuery registered both above and here?
func registerServerMsgHandler(c *onet.Context, smcService *Service) {
	c.RegisterProcessor(smcService, msgTypes.msgSetupRequest)
	c.RegisterProcessor(smcService, msgTypes.msgKeyQuery)
	c.RegisterProcessor(smcService, msgTypes.msgKeyReply)
	c.RegisterProcessor(smcService, msgTypes.msgStoreQuery)
	c.RegisterProcessor(smcService, msgTypes.msgStoreReply)
	c.RegisterProcessor(smcService, msgTypes.msgPlaintextQuery)
	c.RegisterProcessor(smcService, msgTypes.msgPlaintextReply)
	c.RegisterProcessor(smcService, msgTypes.msgSumQuery)
	c.RegisterProcessor(smcService, msgTypes.msgSumReply)
	c.RegisterProcessor(smcService, msgTypes.msgMultiplyQuery)
	c.RegisterProcessor(smcService, msgTypes.msgMultiplyReply)
	c.RegisterProcessor(smcService, msgTypes.msgRelinQuery)
	c.RegisterProcessor(smcService, msgTypes.msgRefreshQuery)
	c.RegisterProcessor(smcService, msgTypes.msgRotationQuery)
	c.RegisterProcessor(smcService, msgTypes.msgRotationReply)
}

// Process processes messages from servers. It is called by the onet library upon reception of any of
// the messages registered in registerServerMsgHandler. For this reason, the Process method
// is bound to be a giant if-else-if, which "manually" dispatches based on the message type.
func (s *Service) Process(msg *network.Envelope) {
	if msg.MsgType.Equal(msgTypes.msgSetupRequest) {
		s.processSetupQuery(msg)
	} else if msg.MsgType.Equal(msgTypes.msgStoreQuery) {
		s.processStoreQuery(msg)
	} else if msg.MsgType.Equal(msgTypes.msgStoreReply) {
		s.processStoreReply(msg)
	} else if msg.MsgType.Equal(msgTypes.msgMultiplyQuery) {
		s.processMultiplyQuery(msg)
	} else if msg.MsgType.Equal(msgTypes.msgMultiplyReply) {
		s.processMultiplyReply(msg)
	} else if msg.MsgType.Equal(msgTypes.msgSumQuery) {
		s.processSumQuery(msg)
	} else if msg.MsgType.Equal(msgTypes.msgSumReply) {
		s.processSumReply(msg)
	} else if msg.MsgType.Equal(msgTypes.msgRotationQuery) {
		s.processRotationQuery(msg)
	} else if msg.MsgType.Equal(msgTypes.msgRotationReply) {
		s.processRotationReply(msg)
	} else if msg.MsgType.Equal(msgTypes.msgKeyQuery) {
		s.processKeyQuery(msg)
	} else if msg.MsgType.Equal(msgTypes.msgKeyReply) {
		s.processKeyReply(msg)
	} else if msg.MsgType.Equal(msgTypes.msgPlaintextQuery) {
		s.processPlaintextQuery(msg)
	} else if msg.MsgType.Equal(msgTypes.msgPlaintextReply) {
		s.processPlaintextReply(msg)
	} else if msg.MsgType.Equal(msgTypes.msgRelinQuery) {
		s.processRelinQuery(msg)
	} else if msg.MsgType.Equal(msgTypes.msgRefreshQuery) {
		s.processRefreshQuery(msg)
	} else {
		log.Error("Unknown message type:", msg.MsgType)
	}
}
