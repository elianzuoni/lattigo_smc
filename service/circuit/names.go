package circuit

import (
	"errors"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
	"lattigo-smc/service/messages"
	"strconv"
	"strings"
)

// Retrieves a CipherID, whether local or remote, given its full name
func (c *Circuit) GetCipherID(fullName string) (messages.CipherID, bool) {
	log.Lvl2(c.service.ServerIdentity(), "(fullName =", fullName, ")\n", "Retrieving CipherID")

	// Parse full name
	name, owner, err := c.parseVarFullName(fullName)
	if err != nil {
		log.Error(c.service.ServerIdentity(), "(fullName =", fullName, ")\n", "Could not parse full variable name:", err)
		return messages.NilCipherID, false
	}

	// If we are owner, retrieve it locally
	if owner.Equal(c.service.ServerIdentity()) {
		log.Lvl2(c.service.ServerIdentity(), "(fullName =", fullName, ")\n", "CipherID is local")
		return c.GetLocalCipherID(name)
	}

	// Else, send a request to the owner
	log.Lvl2(c.service.ServerIdentity(), "(fullName =", fullName, ")\n", "CipherID is remote")
	return c.service.GetRemoteCipherID(c.CircuitID, name, owner)
}

// Retrieves a local CipherID, given its variable name
func (c *Circuit) GetLocalCipherID(name string) (messages.CipherID, bool) {
	c.cipherIDsLock.RLock()
	id, ok := c.cipherIDs[name]
	c.cipherIDsLock.RUnlock()

	return id, ok
}

// Parses the full name to get name and owner
func (c *Circuit) parseVarFullName(fullName string) (name string, owner *network.ServerIdentity, err error) {
	toks := strings.Split(fullName, "@")

	if len(toks) != 2 {
		err = errors.New("Mis-formed full variable name: length != 2 after splitting")
		return
	}

	name = toks[0]
	ownerIdx, err := strconv.Atoi(toks[1])
	if err != nil {
		return
	}
	if ownerIdx < 0 || ownerIdx >= len(c.session.Roster.List) {
		err = errors.New("Mis-formed full variable name: owner index out of bounds")
		return
	}

	owner = c.session.Roster.List[ownerIdx]
	return
}

// Stores a new CipherID under the given name
func (c *Circuit) StoreCipherID(name string, id messages.CipherID) {
	c.cipherIDsLock.Lock()
	c.cipherIDs[name] = id
	c.cipherIDsLock.Unlock()
}
