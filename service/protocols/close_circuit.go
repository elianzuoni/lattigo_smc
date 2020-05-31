// Close-circuit protocol: the parties delete a circuit in their AbstractCircuitStore.
// The steps are:
//
// Method NewCloseCircuitProtocol:
// 0) The nodes initialise the variables needed for the protocol. This method is not usable as-is: it
//    needs to be encapsulated in a proper protocol factory (respecting the onet.NewProtocol signature).
//    For this reason, though CloseCircuitProtocol does implement the onet.ProtocolInstance interface,
//    it is not registered to the onet library, as no protocol factory is yet defined.
// Method Start:
// 1) The root sends the wake-up message to itself.
// Method Dispatch
// 2) Every node waits to receive the wake-up message, then re-sends it to children.
// 3) Every node deletes the circuit, using the AbstractCircuitStore.DeleteCircuit() method.
// 		4a) If leaf, the node sends the Done message to the parent straight away.
//		4b) Else, it first waits to receive the Done message from all children, then it sends it to the parent.

package protocols

import (
	"fmt"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
	"lattigo-smc/service/messages"
)

func init() {
	fmt.Println("CloseCircuit: init")

	_ = network.RegisterMessage(&StructStart{})
	_ = network.RegisterMessage(&StructDone{})
}

// This is a full-blown constructor. In every context, it will have to
// be encapsulated in a proper protocol factory, that only takes the TreeNodeInstance as an argument
// and somehow supplies the rest of the parameters on its own.
func NewCloseCircuitProtocol(t *onet.TreeNodeInstance, store AbstractCircuitStore, CircuitID messages.CircuitID,
) (*CloseCircuitProtocol, error) {
	proto := &CloseCircuitProtocol{
		TreeNodeInstance: t,
		store:            store,
		CircuitID:        CircuitID,
		// No need to initialise the Mutex
	}

	// The zero value of a Mutex is an unlocked one.
	proto.done.Lock()

	// No need to initialise the channels: RegisterChannels will do it for us.
	if err := proto.RegisterChannels(&proto.channelStart, &proto.channelDone); err != nil {
		log.Fatal("Could not register channels: ", err)
		return nil, err
	}

	return proto, nil
}

/****************ONET HANDLERS ******************/

// Start starts the protocol (only called at root).
func (p *CloseCircuitProtocol) Start() error {
	log.Lvl2(p.ServerIdentity(), "Started Close-Circuit protocol")
	//Step 1: send wake-up message to self
	return p.SendTo(p.TreeNode(), &Start{})
}

// Dispatch is called at each node to run the protocol.
// It implements the main protocol logic.
func (p *CloseCircuitProtocol) Dispatch() error {
	log.Lvl3(p.ServerIdentity(), "Started dispatching")

	// Step 2: wait for wake-up, then send it to children
	log.Lvl3(p.ServerIdentity(), "Waiting for wake-up message")
	wakeup := <-p.channelStart
	// Send wake-up message to all children
	log.Lvl3(p.ServerIdentity(), "Sending wake-up message")
	err := p.SendToChildren(&wakeup.Start)
	if err != nil {
		log.ErrFatal(err, p.ServerIdentity(), "Could not send wake up message: ")
		return err
	}

	// Step 3: delete circuit
	log.Lvl3(p.ServerIdentity(), "Deleting circuit")
	p.store.DeleteCircuit(p.CircuitID)

	// Step 4: send the Done message
	log.Lvl3(p.ServerIdentity(), "Sending the Done message")
	if !p.IsLeaf() {
		_ = <-p.channelDone // Block and wait for all children to be done
	}
	p.SendToParent(&Done{})
	// Also signal that the protocol is finished
	p.done.Unlock()

	p.Done() // Onet requirement to finalise the protocol.

	return nil
}

/*********************** Not onet handlers ************************/

// By calling this method, the root can wait for termination of the protocol.
// It is safe to call multiple times.
func (p *CloseCircuitProtocol) WaitDone() {
	log.Lvl3("Waiting for protocol to end")
	p.done.Lock()
	// Unlock again so that subsequent calls to WaitDone do not block forever
	p.done.Unlock()
}

// Check that *CloseCircuitProtocol implements onet.ProtocolInstance
var _ onet.ProtocolInstance = (*CloseCircuitProtocol)(nil)
