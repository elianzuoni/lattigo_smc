package service

import (
	"errors"
	"github.com/ldsec/lattigo/bfv"
	"github.com/ldsec/lattigo/ring"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
	"sync"
)

//Service is the service of lattigoSMC - allows to compute the different HE operations
type Service struct {
	*onet.ServiceProcessor
	onet.Roster

	MasterPublicKey *bfv.PublicKey
	skShard         *bfv.SecretKey
	partialPk       *bfv.PublicKey
	*bfv.EvaluationKey
	Params  *bfv.Parameters
	skSet   bool       // Whether Params (and above fields like skShard) are set
	waitCKG sync.Mutex // CKG protocol factory waits here
	waitEKG sync.Mutex // EKG protocol factory waits here

	rotIdx       int
	k            uint64
	rotParamsSet bool       // Whether rotIdx and k are set
	waitRKG      sync.Mutex // RKG protocol factory waits here

	pubKeyGenerated  bool
	evalKeyGenerated bool
	rotKeyGenerated  bool

	database map[CipherID]*bfv.Ciphertext

	crpGen              *ring.CRPGenerator
	cipherCRPgen        *ring.CRPGenerator
	switchedCiphertext  chan *bfv.Ciphertext
	switchingParameters chan *SwitchingParameters
	rotationKey         *bfv.RotationKeys

	sumReplies      map[SumRequestID]chan CipherID      // TODO: why a map?
	multiplyReplies map[MultiplyRequestID]chan CipherID // TODO: why a map?
	rotationReplies map[RotationRequestID]chan CipherID

	refreshParams       chan *bfv.Ciphertext
	refreshedCiphertext chan *bfv.Ciphertext
}

type SwitchingParameters struct {
	*bfv.PublicKey
	*bfv.Ciphertext
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
		database:         make(map[CipherID]*bfv.Ciphertext),

		switchedCiphertext:  make(chan *bfv.Ciphertext),
		switchingParameters: make(chan *SwitchingParameters, 10), // TODO: why?

		sumReplies:          make(map[SumRequestID]chan CipherID),
		multiplyReplies:     make(map[MultiplyRequestID]chan CipherID),
		refreshParams:       make(chan *bfv.Ciphertext, 3), // TODO: why?
		refreshedCiphertext: make(chan *bfv.Ciphertext),
		rotationReplies:     make(map[RotationRequestID]chan CipherID),
	}

	// The zero value of a Mutex is an unlocked one
	smcService.waitCKG.Lock()
	smcService.waitEKG.Lock()
	smcService.waitRKG.Lock()

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
	if err := smcService.RegisterHandler(smcService.HandleRetrieveQuery); err != nil {
		return errors.New("Couldn't register HandleRetrieveQuery: " + err.Error())
	}
	if err := smcService.RegisterHandler(smcService.HandleKeyQuery); err != nil {
		return errors.New("Couldn't register HandleKeyQuery: " + err.Error())
	}
	if err := smcService.RegisterHandler(smcService.HandleRelinearisationQuery); err != nil {
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
	c.RegisterProcessor(smcService, msgTypes.msgSetupBroadcast)

	c.RegisterProcessor(smcService, msgTypes.msgKeyRequest)
	c.RegisterProcessor(smcService, msgTypes.msgKeyReply)

	c.RegisterProcessor(smcService, msgTypes.msgStoreRequest)

	c.RegisterProcessor(smcService, msgTypes.msgRetrieveRequest)
	c.RegisterProcessor(smcService, msgTypes.msgRetrieveBroadcast)
	c.RegisterProcessor(smcService, msgTypes.msgRetrieveReply)

	c.RegisterProcessor(smcService, msgTypes.msgSumRequest)
	c.RegisterProcessor(smcService, msgTypes.msgSumReply)

	c.RegisterProcessor(smcService, msgTypes.msgMultiplyRequest)
	c.RegisterProcessor(smcService, msgTypes.msgMultiplyReply)

	c.RegisterProcessor(smcService, msgTypes.msgRelinRequest)

	c.RegisterProcessor(smcService, msgTypes.msgRefreshRequest)
	c.RegisterProcessor(smcService, msgTypes.msgRefreshBroadcast)
	c.RegisterProcessor(smcService, msgTypes.msgRefreshReply)

	c.RegisterProcessor(smcService, msgTypes.msgRotationReply)
	c.RegisterProcessor(smcService, msgTypes.msgRotationReply)
}

// Process processes messages from servers. It is called by the onet library upon reception of any of
// the messages registered in registerServerMsgHandler. For this reason, the Process method
// is bound to be a giant if-else-if, which "manually" dispatches based on the message type.
func (s *Service) Process(msg *network.Envelope) {
	if msg.MsgType.Equal(msgTypes.msgSetupRequest) {
		s.processSetupRequest(msg)
	} else if msg.MsgType.Equal(msgTypes.msgSetupBroadcast) {
		s.processSetupBroadcast(msg)
	} else if msg.MsgType.Equal(msgTypes.msgKeyRequest) {
		s.processKeyRequest(msg)
	} else if msg.MsgType.Equal(msgTypes.msgKeyReply) {
		s.processKeyReply(msg)
	} else if msg.MsgType.Equal(msgTypes.msgStoreRequest) {
		s.processStoreRequest(msg)
	} else if msg.MsgType.Equal(msgTypes.msgRetrieveRequest) {
		s.processRetrieveRequest(msg)
	} else if msg.MsgType.Equal(msgTypes.msgRetrieveBroadcast) {
		s.processRetrieveBroadcast(msg)
	} else if msg.MsgType.Equal(msgTypes.msgRetrieveReply) {
		s.processRetrieveReply(msg)
	} else if msg.MsgType.Equal(msgTypes.msgSumRequest) {
		s.processSumRequest(msg)
	} else if msg.MsgType.Equal(msgTypes.msgSumReply) {
		s.processSumReply(msg)
	} else if msg.MsgType.Equal(msgTypes.msgMultiplyRequest) {
		s.processMultiplyRequest(msg)
	} else if msg.MsgType.Equal(msgTypes.msgMultiplyReply) {
		s.processMultiplyReply(msg)
	} else if msg.MsgType.Equal(msgTypes.msgRelinRequest) {
		s.processRelinRequest(msg)
	} else if msg.MsgType.Equal(msgTypes.msgRefreshRequest) {
		s.processRefreshRequest(msg)
	} else if msg.MsgType.Equal(msgTypes.msgRefreshBroadcast) {
		s.processRefreshBroadcast(msg)
	} else if msg.MsgType.Equal(msgTypes.msgRefreshReply) {
		s.processRefreshReply(msg)
	} else if msg.MsgType.Equal(msgTypes.msgRotationRequest) {
		s.processRotationRequest(msg)
	} else if msg.MsgType.Equal(msgTypes.msgRotationReply) {
		s.processRotationReply(msg)
	} else {
		log.Error("Unknown message type:", msg.MsgType)
	}
}
