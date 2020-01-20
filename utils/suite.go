//Contains the suite used thorough the project. Change it if you want to use a different one.
package utils

import "go.dedis.ch/kyber/v3/suites"

var SUITE = suites.MustFind("Ed25519")
