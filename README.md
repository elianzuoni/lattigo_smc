# Lattigo-SMC: MHE-based SMC

Lattigo-SMC is a Go module implementing the Secure Multiparty Computation scheme described in [Multiparty Homomorphic Encryption: From Theory to Practice](https://eprint.iacr.org/2020/304).  
In the SMC problem, a group of mutually untrusting parties need to evaluate a joint function of some inputs they possess, without revealing them.  
In this setting, parties are organised in a peer-to-peer network (they all carry out computations, and no root is a priori defined among them).
Every party has a server side, that cooperates in the collective execution of queries made to the system, and a client side, to issue queries to the system.

The local cryptographic operations are provided by the [Lattigo](https://github.com/ldsec/lattigo) library, while the network operations and patterns are provided by the [Onet](https://github.com/dedis/onet) library.
  
## Overview

The module comprises the following packages:

- [`app`](app): A CLI interface for Lattigo-SMC, to launch servers and clients. NOT UP TO DATE.

- [`protocols`](protocols): The Network Layer, implementing the protocols for the interactive operations described in the [paper](https://eprint.iacr.org/2020/304).

- [`service`](service): The Service Layer, exposing an API to clients. The API enables the evaluation of arbitrary arithmetic circuits.

- [`simulation`](simulation): Simulations to benchmark the execution of protocols and the evaluation of a circuit. Can be deployed on remote clusters (mininet or deterlab).

- [`utils`](utils): Supporting structures and functions.

### `app`

This package is not up to date. It used to provide a CLI application to launch servers and clients. 
However, priority was given first to functional developments (in order to obtain a fully working system), and then to the simulations (to test the performances): for this reason, this package has not been maintained.

### `protocols`

This package implements all the 8 protocols described in the [paper](https://eprint.iacr.org/2020/304) that interactively carry out the operations involving the secret key.
It constitutes the Network Layer.

### `service`

This package defines two services, both accepting queries from clients.  
The Session Service manages sessions (virtual computation environments), and the distribution of ciphertexts and public keys.  
The Circuit Service maintains a naming infrastructure for variables, and offers a high-parallelism distributed circuit evaluation capability to clients.

### `simulation`

This package defines simulations that benchmark the execution of resource-intensive operations.  
There is one defined for each of the 8 protocols, and one for the evaluation of a specific circuit.

### `utils`

This package defines some utility structures and functions, mainly used for testing.