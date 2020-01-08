package services

import (
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
)

//MsgTypes different messages that can be used for the service.
type MsgTypes struct {
	msgQueryData     network.MessageTypeID
	msgSetupRequest  network.MessageTypeID
	msgQuery         network.MessageTypeID
	msgSumQuery      network.MessageTypeID
	msgMultiplyQuery network.MessageTypeID
	msgStoreReply    network.MessageTypeID
	msgKeyRequest    network.MessageTypeID
	msgKeyReply      network.MessageTypeID

	msgQueryPlaintext network.MessageTypeID
	msgReplyPlaintext network.MessageTypeID
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
	msgTypes.msgQuery = network.RegisterMessage(&StoreQuery{})
	msgTypes.msgQueryData = network.RegisterMessage(&QueryData{})
	msgTypes.msgSetupRequest = network.RegisterMessage(&SetupRequest{})
	msgTypes.msgSumQuery = network.RegisterMessage(&SumQuery{})
	msgTypes.msgMultiplyQuery = network.RegisterMessage(&MultiplyQuery{})
	msgTypes.msgStoreReply = network.RegisterMessage(&StoreReply{})

	msgTypes.msgKeyRequest = network.RegisterMessage(&KeyRequest{})
	msgTypes.msgKeyReply = network.RegisterMessage(&KeyReply{})
	msgTypes.msgQueryPlaintext = network.RegisterMessage(&QueryPlaintext{})
	msgTypes.msgReplyPlaintext = network.RegisterMessage(&ReplyPlaintext{})
}
