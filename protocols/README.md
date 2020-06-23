# Protocols 

This package implements the protocols for the 8 interactive operations that involve the secret key, as described in the [paper](https://eprint.iacr.org/2020/304). 
The Onet-related coding patterns are taken from the [cothority_template](https://github.com/dedis/cothority_template). 

Every protocol follows the same structure: parties combine their secret key share with some public input to obtain their (public) *protocol share*; 
the result is defined as the *aggregation* of the protocol shares (aggregation always takes the form of an addition, i.e. it is associative and commutative).  
To aggregate all the protocol shares, parties organise themselves in a tree topology and perform *intermediate aggregation*: each party aggregates its children's shares together and with its own one, and then sends the aggregate to the parent.  
The result is not broadcast down the tree at the end, so it is only available at the root. 

## Pipeline

There are some minor differences between the protocols I implemented (`EncToShares` and `SharesToEnc`) and the ones implemented in the previous project (all the others).  
The pipeline for a protocol is : 

1) `Init` / Constructor: Initialises the protocol structure.  
The Onet library requires that a factory function, with a specific signature (it cannot be the constructor itself), be registered for every protocol type.
For this reason, the factory needs to somehow supply the remaining parameters (like the public input for the protocol) on its own: this is achieved differently depending on the context in which the protocol is used ([`protocols/test`](test), [`simulation`](../simulation), and [`service`](../service) all define their own protocol factories).  
`EncToShares` and `SharesToEnc` have constructors that set all the fields; the other protocols have constructors that only set some minimal fields, while the rest is set by the `Init` method (which is always called right after the constructor anyway). 
2) `Start`: Only called by the initiator node.  
In `EncToShares` and `SharesToEnc`, it is used by the initiator to send an empty wake-up message to itself; in the other protocols, it does nothing.
3) `Dispatch`: Called at every node; this is where the actual protocol is implemented.  
In `EncToShares` and `SharesToEnc`, it starts by waiting for a wake-up message, then it relays the message to the children nodes; in the other protocols, it directly sends the message to the children.  
After this, each node generates its protocol share using the dedicated function of the [dbfv](https://github.com/ldsec/lattigo/tree/master/dbfv) package of Lattigo.  
Each leaf directly sends its protocol share to its parent; each non-leaf node, instead, waits to receive the protocol shares by all the children, aggregates them together and with its own one using the dedicated function of the [dbfv](https://github.com/ldsec/lattigo/tree/master/dbfv) package, then sends it to its parent.
4) `Done`: Called after the `Dispatch` method to finalise the protocol. No protocol overrides it, as the default one is sufficient.

Additionally, there is a `Wait` method that blocks until the protocol completes the `Dispatch` phase. It is useful for the initiator node to synchronise and wait until the result of the protocol is available. 
