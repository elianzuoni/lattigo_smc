package tree

import "lattigo-smc/service/messages"

// Performs the operation, waiting on the children'channels, and putting the result in the channel.
type Action func(n *Node)

type Node struct {
	Parent   *Node
	Children []*Node

	// Optional fields
	Name string // Contains the variable name at leaves
	// Rotation parameters
	RotIdx int
	K      uint64

	Action Action
	Output chan messages.CipherID
}

func NewNode(name string, parent *Node, nChildren int) *Node {
	return &Node{parent, make([]*Node, 0, nChildren), name, -1, 0, nil,
		make(chan messages.CipherID, 1)}
}

func (n *Node) SetName(name string) {
	n.Name = name
}

func (n *Node) SetRot(rotIdx int, k uint64) {
	n.RotIdx = rotIdx
	n.K = k
}

func (n *Node) SetAction(action Action) {
	n.Action = action
}

func (n *Node) SetParent(parent *Node) {
	n.Parent = parent
}

// The way this is done allows len(Children) to always be the actual number of children (no nils).
func (n *Node) AddChild(child *Node) {
	// If slice is full, resize
	if cap(n.Children) == len(n.Children) {
		// Preserve length, double capacity (with +1, in case it was zero)
		newChildren := make([]*Node, len(n.Children), 1+2*cap(n.Children))
		copy(newChildren, n.Children)
		n.Children = newChildren
	}

	// Re-slice (only by one) to allow for one more child
	n.Children = n.Children[:len(n.Children)+1]

	// Add the new child
	n.Children[len(n.Children)-1] = child

	return
}

func (n *Node) IsRoot() bool {
	return n.Parent == nil
}

func (n *Node) IsLeaf() bool {
	return len(n.Children) == 0
}

func (n *Node) Run() {
	action := n.Action
	action(n)
}

func (n *Node) GetOutput() messages.CipherID {
	return <-n.Output
}
