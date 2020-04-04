# Notes on onet
Some notes I took of Onet while trying to understand it. They may be out of date..

## Simulation 
- Server members = nodes
- Services are run by node - used to start the protocol. 
- Node function can be used to inject info at the start of the protocol to each node from the service 


- To build you need to have the package simulation be main
- then the command is : 
	`./simulation -platform $yourplatform $tomlfile`
	where $yourplatform can be either localhost/mininet
	$tomlfile is the tomlfile used to indicate what protocol to run 


## Service 

- We first have to create structures for message passing - these structures **NEED** to have their BinaryMarshaller overriden if they have complex structures. 
- NewService - use to register the handlers TODO : can we do the CreateSession in the constructor ? maybe not but if not where can it be done ? 
- Process(msg) - check the message type and forward to the corresponding handler this is called when you receive a message from an other server 
- Handlers(Structure)(network.Message, error) - handle a message from a server or client - returns a message that can be sent further 
- NewProtocol : called when there is a new protocol to be run by all nodes. In this case all nodes will start the protocol and based on the GenericConf and the TreeNodeInstance name run the appropriate protocol 
- StartService(root bool) : stars a new service with the steps and protocols. 
This would typically where we could handle a query for a key switching or to multiply some ciphertext etc.
- Phases - different phases of the service. they will call the underlying protocol to do what is necessary. 
