package circuit

import (
	"errors"
	"fmt"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
	"lattigo-smc/service/messages"
	"lattigo-smc/service/session"
	"sync"
	// Imports just to execute their init functions
	_ "lattigo-smc/protocols"
	_ "lattigo-smc/service/protocols"
)

type Service struct {
	*onet.ServiceProcessor

	sumRepLock         sync.RWMutex
	sumReplies         map[messages.SumRequestID]chan *messages.SumReply
	multiplyRepLock    sync.RWMutex
	multiplyReplies    map[messages.MultiplyRequestID]chan *messages.MultiplyReply
	relinRepLock       sync.RWMutex
	relinReplies       map[messages.RelinRequestID]chan *messages.RelinReply
	rotationRepLock    sync.RWMutex
	rotationReplies    map[messages.RotationRequestID]chan *messages.RotationReply
	switchRepLock      sync.RWMutex
	switchReplies      map[messages.SwitchRequestID]chan *messages.SwitchReply
	refreshRepLock     sync.RWMutex
	refreshReplies     map[messages.RefreshRequestID]chan *messages.RefreshReply
	encToSharesRepLock sync.RWMutex
	encToSharesReplies map[messages.EncToSharesRequestID]chan *messages.EncToSharesReply
	sharesToEncRepLock sync.RWMutex
	sharesToEncReplies map[messages.SharesToEncRequestID]chan *messages.SharesToEncReply
}

const ServiceName = "CircuitService"

// Registers the LattigoSMC service to the onet library
func init() {
	fmt.Println("CircuitService: init")

	_, err := onet.RegisterNewService(ServiceName, NewService)
	if err != nil {
		log.Error("Could not register the service")
		panic(err)
	}
}

// Constructor of Circuit Service
func NewService(c *onet.Context) (onet.Service, error) {
	log.Lvl1(c.ServerIdentity(), "CircuitService constructor started")

	service := &Service{
		ServiceProcessor: onet.NewServiceProcessor(c),

		// Synchronisation points on which a reply from a contacted server is waited for
		sumReplies:         make(map[messages.SumRequestID]chan *messages.SumReply),
		multiplyReplies:    make(map[messages.MultiplyRequestID]chan *messages.MultiplyReply),
		relinReplies:       make(map[messages.RelinRequestID]chan *messages.RelinReply),
		rotationReplies:    make(map[messages.RotationRequestID]chan *messages.RotationReply),
		switchReplies:      make(map[messages.SwitchRequestID]chan *messages.SwitchReply),
		refreshReplies:     make(map[messages.RefreshRequestID]chan *messages.RefreshReply),
		encToSharesReplies: make(map[messages.EncToSharesRequestID]chan *messages.EncToSharesReply),
		sharesToEncReplies: make(map[messages.SharesToEncRequestID]chan *messages.SharesToEncReply),
	}

	// Registers the handlers for client requests.
	e := registerClientQueryHandlers(service)
	if e != nil {
		log.Error("Error registering handlers for client queries")
		return nil, e
	}
	// Registers the (unique) handler for server's messages.
	registerServerMsgHandler(c, service)

	return service, nil
}

// Registers in smcService handlers - of the form func(msg interface{})(ret interface{}, err error) -
// for every possible type of client request, implicitly identified by the type of msg.
func registerClientQueryHandlers(service *Service) error {
	if err := service.RegisterHandler(service.HandleSumQuery); err != nil {
		return errors.New("Couldn't register HandleSumQuery: " + err.Error())
	}
	if err := service.RegisterHandler(service.HandleMultiplyQuery); err != nil {
		return errors.New("Couldn't register HandleMultiplyQuery: " + err.Error())
	}
	if err := service.RegisterHandler(service.HandleSwitchQuery); err != nil {
		return errors.New("Couldn't register HandleSwitchQuery: " + err.Error())
	}
	if err := service.RegisterHandler(service.HandleRelinQuery); err != nil {
		return errors.New("Couldn't register HandleRelinearizationquery: " + err.Error())
	}
	if err := service.RegisterHandler(service.HandleRefreshQuery); err != nil {
		return errors.New("Couldn't register HandleRefreshQuery: " + err.Error())
	}
	if err := service.RegisterHandler(service.HandleRotationQuery); err != nil {
		return errors.New("Couldn't register HandleRotationQuery: " + err.Error())
	}
	if err := service.RegisterHandler(service.HandleEncToSharesQuery); err != nil {
		return errors.New("Couldn't register HandleEncToSharesQuery: " + err.Error())
	}
	if err := service.RegisterHandler(service.HandleSharesToEncQuery); err != nil {
		return errors.New("Couldn't register HandleSharesToEncQuery: " + err.Error())
	}
	if err := service.RegisterHandler(service.HandleCircuitQuery); err != nil {
		return errors.New("Couldn't register HandleCircuitQuery: " + err.Error())
	}

	return nil
}

// Registers smcService to the underlying onet.Context as a processor for all the possible types of messages
// received by another server (every client request is forwarded to the root, so every query entails some
// server-root interaction). Upon reception of one of these messages, the method Process will be invoked.
func registerServerMsgHandler(c *onet.Context, service *Service) {
	// Retrieve
	c.RegisterProcessor(service, messages.MsgTypes.MsgRetrieveRequest)
	c.RegisterProcessor(service, messages.MsgTypes.MsgRetrieveReply)

	// Sum
	c.RegisterProcessor(service, messages.MsgTypes.MsgSumRequest)
	c.RegisterProcessor(service, messages.MsgTypes.MsgSumReply)

	// Multiply
	c.RegisterProcessor(service, messages.MsgTypes.MsgMultiplyRequest)
	c.RegisterProcessor(service, messages.MsgTypes.MsgMultiplyReply)

	// Relinearise
	c.RegisterProcessor(service, messages.MsgTypes.MsgRelinRequest)
	c.RegisterProcessor(service, messages.MsgTypes.MsgRelinReply)

	// Refresh
	c.RegisterProcessor(service, messages.MsgTypes.MsgRefreshRequest)
	c.RegisterProcessor(service, messages.MsgTypes.MsgRefreshReply)

	// Rotation
	c.RegisterProcessor(service, messages.MsgTypes.MsgRotationRequest)
	c.RegisterProcessor(service, messages.MsgTypes.MsgRotationReply)

	// Encryption to shares
	c.RegisterProcessor(service, messages.MsgTypes.MsgEncToSharesRequest)
	c.RegisterProcessor(service, messages.MsgTypes.MsgEncToSharesReply)

	// Shares to encryption
	c.RegisterProcessor(service, messages.MsgTypes.MsgSharesToEncRequest)
	c.RegisterProcessor(service, messages.MsgTypes.MsgSharesToEncReply)
}

// Process processes messages from servers. It is called by the onet library upon reception of any of
// the messages registered in registerServerMsgHandler. For this reason, the Process method
// is bound to be a giant if-else-if, which "manually" dispatches based on the message type.
func (service *Service) Process(msg *network.Envelope) {
	// Retrieve
	if msg.MsgType.Equal(messages.MsgTypes.MsgRetrieveRequest) {
		service.processSwitchRequest(msg)
		return
	}
	if msg.MsgType.Equal(messages.MsgTypes.MsgRetrieveReply) {
		service.processSwitchReply(msg)
		return
	}

	// Sum
	if msg.MsgType.Equal(messages.MsgTypes.MsgSumRequest) {
		service.processSumRequest(msg)
		return
	}
	if msg.MsgType.Equal(messages.MsgTypes.MsgSumReply) {
		service.processSumReply(msg)
		return
	}

	// Multiply
	if msg.MsgType.Equal(messages.MsgTypes.MsgMultiplyRequest) {
		service.processMultiplyRequest(msg)
		return
	}
	if msg.MsgType.Equal(messages.MsgTypes.MsgMultiplyReply) {
		service.processMultiplyReply(msg)
		return
	}

	// Relinearise
	if msg.MsgType.Equal(messages.MsgTypes.MsgRelinRequest) {
		service.processRelinRequest(msg)
		return
	}
	if msg.MsgType.Equal(messages.MsgTypes.MsgRelinReply) {
		service.processRelinReply(msg)
		return
	}

	// Refresh
	if msg.MsgType.Equal(messages.MsgTypes.MsgRefreshRequest) {
		service.processRefreshRequest(msg)
		return
	}
	if msg.MsgType.Equal(messages.MsgTypes.MsgRefreshReply) {
		service.processRefreshReply(msg)
		return
	}

	// Rotation
	if msg.MsgType.Equal(messages.MsgTypes.MsgRotationRequest) {
		service.processRotationRequest(msg)
		return
	}
	if msg.MsgType.Equal(messages.MsgTypes.MsgRotationReply) {
		service.processRotationReply(msg)
		return
	}

	// Encryption to shares
	if msg.MsgType.Equal(messages.MsgTypes.MsgEncToSharesRequest) {
		service.processEncToSharesRequest(msg)
		return
	}
	if msg.MsgType.Equal(messages.MsgTypes.MsgEncToSharesReply) {
		service.processEncToSharesReply(msg)
		return
	}

	// Shares to encryption
	if msg.MsgType.Equal(messages.MsgTypes.MsgSharesToEncRequest) {
		service.processSharesToEncRequest(msg)
		return
	}
	if msg.MsgType.Equal(messages.MsgTypes.MsgSharesToEncReply) {
		service.processSharesToEncReply(msg)
		return
	}

	log.Error("Unknown message type:", msg.MsgType)
}

func (service *Service) GetSessionService() *session.Service {
	return service.Service(session.ServiceName).(*session.Service)
}
