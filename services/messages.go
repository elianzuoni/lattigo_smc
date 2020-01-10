//Contains the various messages used by the service and client architecture.
package services

import (
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
)

//MsgTypes different messages that can be used for the service.
type MsgTypes struct {
	msgSetupRequest network.MessageTypeID
	msgQuery        network.MessageTypeID

	//
	msgKeyRequest network.MessageTypeID
	msgKeyReply   network.MessageTypeID

	//Message to store ciphers
	msgQueryData  network.MessageTypeID
	msgStoreReply network.MessageTypeID
	//Message for the key switch
	msgQueryPlaintext network.MessageTypeID
	msgReplyPlaintext network.MessageTypeID

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
	msgTypes.msgQueryData = network.RegisterMessage(&QueryData{})

	msgTypes.msgSetupRequest = network.RegisterMessage(&SetupRequest{})
	msgTypes.msgKeyRequest = network.RegisterMessage(&KeyRequest{})
	msgTypes.msgKeyReply = network.RegisterMessage(&KeyReply{})

	msgTypes.msgQuery = network.RegisterMessage(&StoreQuery{})
	msgTypes.msgStoreReply = network.RegisterMessage(&StoreReply{})

	msgTypes.msgQueryPlaintext = network.RegisterMessage(&QueryPlaintext{})
	msgTypes.msgReplyPlaintext = network.RegisterMessage(&ReplyPlaintext{})

	msgTypes.msgSumQuery = network.RegisterMessage(&SumQuery{})
	msgTypes.msgSumReply = network.RegisterMessage(&SumReply{})
	msgTypes.msgMultiplyQuery = network.RegisterMessage(&MultiplyQuery{})
	msgTypes.msgMultiplyReply = network.RegisterMessage(&MultiplyReply{})

	msgTypes.msgRelinQuery = network.RegisterMessage(&RelinQuery{})
	msgTypes.msgRefreshQuery = network.RegisterMessage(&RefreshQuery{})

	msgTypes.msgRotationQuery = network.RegisterMessage(&RotationQuery{})
	msgTypes.msgRotationReply = network.RegisterMessage(&RotationReply{})
}
