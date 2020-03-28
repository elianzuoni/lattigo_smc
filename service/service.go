package service

import (
	"errors"
	"github.com/ldsec/lattigo/bfv"
	"github.com/ldsec/lattigo/ring"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
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
	DataBase            map[CipherID]*bfv.Ciphertext
	Ckgp                *protocols.CollectiveKeyGenerationProtocol
	crpGen              ring.CRPGenerator
	SwitchedCiphertext  map[CipherID]chan bfv.Ciphertext
	SwitchingParameters chan SwitchingParameters
	RotationKey         *bfv.RotationKeys

	SumReplies      map[SumRequestID]chan CipherID
	MultiplyReplies map[MultiplyRequestID]chan CipherID
	RotationReplies map[CipherID]chan CipherID

	RefreshParams chan *bfv.Ciphertext
	RotIdx        int
	K             uint64
}

const ServiceName = "LattigoSMC"

// Registers the LattigoSMC service to the onet library
func init() {
	_, err := onet.RegisterNewService(ServiceName, NewLattigoSMCService)
	if err != nil {
		log.Error("Could not start the service")
		panic(err)
	}
}

func NewLattigoSMCService(c *onet.Context) (onet.Service, error) {
	log.Lvl1(c.ServerIdentity(), "Starting LattigoSMC service")

	smcService := &Service{
		ServiceProcessor: onet.NewServiceProcessor(c),
		DataBase:         make(map[CipherID]*bfv.Ciphertext),

		SwitchedCiphertext:  make(map[CipherID]chan bfv.Ciphertext),
		SwitchingParameters: make(chan SwitchingParameters, 10),

		SumReplies:      make(map[SumRequestID]chan CipherID),
		MultiplyReplies: make(map[MultiplyRequestID]chan CipherID),
		RefreshParams:   make(chan *bfv.Ciphertext, 3),
		RotationReplies: make(map[CipherID]chan CipherID),
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
	// TODO: complete

	c.RegisterProcessor(smcService, msgTypes.msgKeyRequest)
	c.RegisterProcessor(smcService, msgTypes.msgKeyReply)

	c.RegisterProcessor(smcService, msgTypes.msgStoreRequest)

	c.RegisterProcessor(smcService, msgTypes.msgSumRequest)
	c.RegisterProcessor(smcService, msgTypes.msgSumReply)

	c.RegisterProcessor(smcService, msgTypes.msgMultiplyRequest)
	c.RegisterProcessor(smcService, msgTypes.msgMultiplyReply)
}

// Process processes messages from servers. It is called by the onet library upon reception of any of
// the messages registered in registerServerMsgHandler. For this reason, the Process method
// is bound to be a giant if-else-if, which "manually" dispatches based on the message type.
func (s *Service) Process(msg *network.Envelope) {
	if msg.MsgType.Equal(msgTypes.msgSetupRequest) {
		s.processSetupQuery(msg)
	} else if msg.MsgType.Equal(msgTypes.msgStoreRequest) {
		s.processStoreRequest(msg)
	} else if msg.MsgType.Equal(msgTypes.msgMultiplyRequest) {
		s.processMultiplyRequest(msg)
	} else if msg.MsgType.Equal(msgTypes.msgMultiplyReply) {
		s.processMultiplyReply(msg)
	} else if msg.MsgType.Equal(msgTypes.msgSumRequest) {
		s.processSumRequest(msg)
	} else if msg.MsgType.Equal(msgTypes.msgSumReply) {
		s.processSumReply(msg)
	} else if msg.MsgType.Equal(msgTypes.msgRotationQuery) {
		s.processRotationQuery(msg)
	} else if msg.MsgType.Equal(msgTypes.msgRotationReply) {
		s.processRotationReply(msg)
	} else if msg.MsgType.Equal(msgTypes.msgKeyRequest) {
		s.processKeyRequest(msg)
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
