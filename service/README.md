# Service 
Service logic for Lattigo-SMC. Servers are connected, and each one exposes a valid entry point to the whole system.
Some queries need interaction, whereas others could be performed locally. Nonetheless, query execution is always
delegated to the root of the tree.

## Exchanged messages

The interaction between the involved nodes works as follows:

* The `Client` sends a `Query` message to any of the servers, using the method `SendQuery`. 
The server only returns when it has a full-fledged `Response` message to send back: 
no "progress update" message is sent to the `Client`.

* The server handles the `Query` in the method `HandleQuery`: it encapsulates the `Query` in a `Request`, 
endowed with a `RequestID`, which is forwarded to the root. 
To achieve the blocking behaviour of the queries, `HandleQuery` blocks on the channel `replies`, 
on which the method `processReply`, which processes the `Reply` message from the root 
in a different goroutine, sends the `Reply` itself.

* The root processes the `Request` in the method `processRequest`. 
If the query only entails local computation, the root executes them and then returns a `Reply` to the server.  
Otherwise, if one of the protocols is required, a preliminary `Broadcast` message is sent to all nodes
(including the root) to set up the variables needed for the execution of the protocol. 
Then, the protocol itself is launched, and `processReply` waits for its termination and collects its result. 
Finally, a `Reply` is constructed and sent back to the server.

* The servers process the `Broadcast` message, if applicable for that query, in `processBroadcast`. 
All it does is to extract from the message the relevant parameters for the upcoming protocol, and 
either send them through the channel `params`, or directly set them into the `Service` structure
and unlock the Mutex `wait`. This synchronisation mechanism is needed because there is no guarantee 
on the relative timing between the reception of the `Broadcast` message and the start of the protocol.
Thus, the protocol factory either reads the variables it needs from the `params` channel, or locks the
`wait` Mutex before accessing them in the `Service` structure.

* The server processes the `Reply` message in the method `processReply`, which is executed
in a different goroutine than `HandleQuery` (which is still running and, probably, waiting
on the channel `replies`). All it does is to send the `Reply` through the channel, so as to wake up
the goroutine executing the method `HandleQuery`.

* When `HandleQuery` wakes up and receives the `Reply` from the `replies` channel, it uses it to construct
the `Response` message to send back to the `Client`. 


## Files

 
The files' content is summarised below:
 
- [api.go](api.go) : Contains the client-side methods to send queries to a server. 
- [marshaller.go](marshaller.go) : Marshalling of all the message structures. 
- [messages.go](messages.go) : Defines all the message structures, and registers them to the `onet` library. 
- [protocols.go](protocols.go) : Defines the protocol factories. Actually, it is only one (`NewProtocol`), which
decides what specific factory (also defined in this file) to call, based on the protocol name.
- [query_e2s.go](query_e2s.go) : Defines the behaviour for the `EncryptionToShares` query. 
- [query_key.go](query_key.go) : Defines the behaviour for the `Key` query. 
- [query_mult.go](query_mult.go) : Defines the behaviour for the `Multiply` query. 
- [query_refresh.go](query_refresh.go) : Defines the behaviour for the `Refresh` query. 
- [query_relin.go](query_relin.go) : Defines the behaviour for the `Relinearise` query. 
- [query_retrieve.go](query_retrieve.go) : Defines the behaviour for the `Retrieve` query. 
- [query_rot.go](query_rot.go) : Defines the behaviour for the `Rotation` query. 
- [query_s2e.go](query_s2e.go) : Defines the behaviour for the `SharesToEncryption` query. 
- [query_createsession.go](query_createsession.go) : Defines the behaviour for the `CreateSession` query. 
- [query_store.go](query_store.go) : Defines the behaviour for the `Store` query. 
- [query_sum.go](query_sum.go) : Defines the behaviour for the `Sum` query. 
- [service.go](service.go) : Defines the `Service` structure. Registers the handlers for messages 
from clients and other servers
- [service_test.go](service_test.go) : Test for the whole package. 

