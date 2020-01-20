# Service 
Service logic for Lattigo-SMC. The files are documented but here I explain what they are used for to make code navigation easier.
The interation is the following : a server implements a service. The client connects to a server through an API. The servers communicate between each others to execute the different protocols and functionalities needed. 

In the scope of this project, I always implemented tree-like networks with a central root. The root will always store all the ciphertexts and will be responsible to start the protocols, do the evaluations and the operations required by the other servers. 
For an other server when he makes a query, he contacts the root which will perform the query and reply if needed. 
The files are summarized below : 
- `api.go` : Contains the client side handlers. These methods are called when a client creates a query that will be sent to a server. 
- `evaluation.go`: Handlers for all the different evaluation operation the operations are the following : 
    - Sum of two ciphertexts : replies with the UUID of the newly stored ciphertext 
    - Multply of two ciphertext : replies with UUID of the newly stored ciphertext 
    - Relinearize a ciphertext : replies with the UUID of the newly stored ciphertext 
    - Refresh a ciphertext : replies with the *same* UUID as the ciphertext will be relinearized and stored back. 
    - Rotate a ciphertext : replies with the UUID of the newly stored ciphertext
- `marshaller.go` : Marshalling of the structures needed to be sent by the services. 
- `messages.go` : Registers the handlers and the messages uses between servers. 
- `process.go` : Process is the method for server-server messaging. When a new server-server message arrives it goes through this file. You first need to register the needed messages in `messages.go`. 
- `retrievedata.go` : Handler to retrieve the data stored at the root. 
- `service.go` : Constructor for a new service. also contains the registering methods and the structure of the Service. 
- `setup.go` : Handler for the setup of the service. The request for setup should be done by a client directly connecting to the root. You can specify which keys you want. 
- `storedata.go` : handler to store data on the root. 
- `struct.go` : Contains the structures that are sent through the network. If you are going to use different structure, you will most likely need to override the MarshalBinary.