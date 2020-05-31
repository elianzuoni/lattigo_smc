package circuit

import (
	"errors"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
	"lattigo-smc/service/messages"
)

func (service *Service) HandleNameQuery(query *messages.NameQuery) (network.Message, error) {
	log.Lvl2(service.ServerIdentity(), "Received SNameQuery")

	// Extract Circuit, if existent
	c, ok := service.GetCircuit(query.CircuitID)
	if !ok {
		err := errors.New("Requested circuit does not exist")
		log.Error(service.ServerIdentity(), err)
		return nil, err
	}

	// Store ID under name
	c.StoreCipherID(query.Name, query.CipherID)

	return &messages.NameResponse{true}, nil
}
