// Package protocols contains the protocols for lattigo - secure multi party computation
//
// This package contains the protocols used to run the different parts that require interaction between different parties
// The nodes ( or parties ) can :
// 	- generate a collective public key that can be used to encrypt plaintext under a same trust boundary (collective_key_gen)
//	- generate a realinearization key that can, in a trust boundary, linearize a ciphertext after a multiplicative evaluation ( relinearization_key )
// 	- switch the key under which a ciphertext is encrypted to a different secret key ( collective_key_switch )
//	- switch the key under which a ciphertext is encrypted to a different public key ( collective_public_key_switch )
//	- refresh a ciphertext to remove the noise
//	- generate a rotation key that can be used to perform a rotation on the plaintext vector without leaking plaintext.
// The nodes are generated in a tree like fashion and the message passing is done with onet.
package protocols
