//Contains the various messages used by the service and client architecture.
package service

import (
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
	"lattigo-smc/protocols"
)

//MsgTypes different messages that can be used for the service.
type MsgTypes struct {
	//Message for setup the keys.
	msgSetupRequest network.MessageTypeID

	//Messages to request keys
	msgKeyQuery network.MessageTypeID
	msgKeyReply network.MessageTypeID

	//Message to store ciphers
	msgStoreQueryClient network.MessageTypeID //Store query when it comes from client.
	msgStoreQuery       network.MessageTypeID
	msgStoreReply       network.MessageTypeID
	//Message for the key switch
	msgPlaintextQuery network.MessageTypeID
	msgPlaintextReply network.MessageTypeID

	//Messages for evaluations
	msgSumQuery      network.MessageTypeID
	msgMultiplyQuery network.MessageTypeID
	msgSumReply      network.MessageTypeID
	msgMultiplyReply network.MessageTypeID
	msgRelinQuery    network.MessageTypeID
	msgRefreshQuery  network.MessageTypeID
	msgRotationReply network.MessageTypeID
	msgRotationQuery network.MessageTypeID
}

var msgTypes = MsgTypes{}

func init() {
	_, err := onet.RegisterNewService(ServiceName, NewLattigoSMCService)
	if err != nil {
		log.Error("Could not start the service")
		panic(err)
	}

	//Register the messages
	log.Lvl1("Registering messages")
	msgTypes.msgStoreQueryClient = network.RegisterMessage(&QueryData{})

	msgTypes.msgSetupRequest = network.RegisterMessage(&SetupRequest{})
	msgTypes.msgKeyQuery = network.RegisterMessage(&KeyRequest{})
	msgTypes.msgKeyReply = network.RegisterMessage(&KeyReply{})

	msgTypes.msgStoreQuery = network.RegisterMessage(&StoreQuery{})
	msgTypes.msgStoreReply = network.RegisterMessage(&StoreReply{})

	msgTypes.msgPlaintextQuery = network.RegisterMessage(&QueryPlaintext{})
	msgTypes.msgPlaintextReply = network.RegisterMessage(&ReplyPlaintext{})

	msgTypes.msgSumQuery = network.RegisterMessage(&SumQuery{})
	msgTypes.msgSumReply = network.RegisterMessage(&SumReply{})
	msgTypes.msgMultiplyQuery = network.RegisterMessage(&MultiplyQuery{})
	msgTypes.msgMultiplyReply = network.RegisterMessage(&MultiplyReply{})

	msgTypes.msgRelinQuery = network.RegisterMessage(&RelinQuery{})
	msgTypes.msgRefreshQuery = network.RegisterMessage(&RefreshQuery{})

	msgTypes.msgRotationQuery = network.RegisterMessage(&RotationQuery{})
	msgTypes.msgRotationReply = network.RegisterMessage(&RotationReply{})

	network.RegisterMessage(&protocols.Start{})
}
