# Lattigo-SMC: A network layer for the [Lattigo](https://github.com/ldsec/lattigo)


Lattigo-SMC is a Go package implementing a network layer for the Lattigo library using [Onet](https://github.com/dedis/onet)
The library features : 
- An implementation of the protocols mentionned in [Computing across trust boundaries](https://eprint.iacr.org/2019/961.pdf). 
- A simulation of the protocols 
- A service architecture of the protocols. 
- A CLI application that can simulate the protocols. 

## Library overview

The library comprises the following sub-packages:

- `lattigo-smc/app`: A CLI interface for Lattigo-SMC. Can run servers and clients that connect to servers. 

- `lattigo-smc/protocols`: The protocols implemented. See the readme for more details. 

- `lattigo-smc/services`: A service of the client and servers. Contains the handlers and messaging logic. See the readme of the package for more details. 

- `lattigo-smc/simulation` : Simulations of the protocols. It is used to get benchmarks and empiric values of the bandwidth. This can also be used to test on mininet or deterlab. 

- `lattigo-smc/examples`: An old implementation of the network layer. It is not relevant anymore. 

- `lattigo-smc/utils`: Supporting structures and functions.