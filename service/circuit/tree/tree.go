package tree

// TODO: add logs

import (
	"errors"
	"go.dedis.ch/onet/v3/log"
	"lattigo-smc/service/messages"
	"strconv"
	"unicode"
)

type BinaryOperation func(id1 messages.CipherID, id2 messages.CipherID) (messages.CipherID, error)
type UnaryOperation func(id messages.CipherID) (messages.CipherID, error)
type Supplier func(name string) (messages.CipherID, error)

type Tree struct {
	Root *Node
	BF   int // Branching factor

	// Actions for every node of the tree
	Get Action
	Add Action
	// TODO: Sub
	Mul Action
	Rot Action
}

func NewTree(BF int, get Supplier, add, mul BinaryOperation, rot UnaryOperation) *Tree {
	actGet := func(n *Node) {
		id, err := get(n.Val)
		if err != nil {
			log.Error("Could not resolve:", err)
			n.Output <- messages.NilCipherID
			return
		}
		n.Output <- id
		return
	}

	actAdd := func(n *Node) {
		if len(n.Children) != 2 {
			// TODO: maybe panic?
			return
		}

		id1 := n.Children[0].GetOutput()
		id2 := n.Children[1].GetOutput()
		idSum, err := add(id1, id2)
		if err != nil {
			log.Error("Could not add:", err)
			n.Output <- messages.NilCipherID
			return
		}
		n.Output <- idSum

		return
	}

	actMul := func(n *Node) {
		if len(n.Children) != 2 {
			// TODO: maybe panic?
			return
		}

		id1 := n.Children[0].GetOutput()
		id2 := n.Children[1].GetOutput()
		idMul, err := mul(id1, id2)
		if err != nil {
			log.Error("Could not multiply:", err)
			n.Output <- messages.NilCipherID
			return
		}
		n.Output <- idMul

		return
	}

	actRot := func(n *Node) {
		if len(n.Children) != 1 {
			// TODO: maybe panic?
			return
		}

		id := n.Children[0].GetOutput()
		idRot, err := rot(id)
		if err != nil {
			log.Error("Could not rotate:", err)
			n.Output <- messages.NilCipherID
			return
		}
		n.Output <- idRot

		return
	}

	return &Tree{nil, BF, actGet, actAdd, actMul, actRot}
}

func NewBinaryTree(Get Supplier, Add, Mul BinaryOperation, Rot UnaryOperation) *Tree {
	return NewTree(2, Get, Add, Mul, Rot)
}

// Just run every Run in a separate goroutine, no matter the order of visit
func (t *Tree) Evaluate() messages.CipherID {
	t.Root.RunSubTree()
	return <-t.Root.Output
}

// Launch a goroutine for every node in the subtree (pre-order visit)
func (n *Node) RunSubTree() {
	go n.Run()
	for _, child := range n.Children {
		child.RunSubTree()
	}
}

// Parsing

// The four types of symbols encountered in a reverse polish notation string. Used for keeping state when parsing.
const (
	LEFT = iota
	RIGHT
	OP
	VAL
)

// The string describes a tree. A tree is defined by
// TREE = VAL | OP (LEFT TREE RIGHT)+
// LEFT = '('
// RIGHT = ')'
// OP = '+' |  '*' | 'R'
// VAL = 'v' <space> <alphaNum> '@' 'n' <number>
//
// lastSeen is the state, indicating the last symbol that was seen.
// currNode is the current node in the tree that is being created.
// LEFT can only be seen after a RIGHT or OP. When seen, a new blank (Action-less) child is added to currNode,
// and currNode is set to that child.
// RIGHT can only be seen after VAL or RIGHT. When seen, currNode is set to currNode's parent.
// OP can only be seen after LEFT. When seen, the right action is set in currNode.
// VAL can only be seen after LEFT. When seen, the actGet action is set in currNode, as well as the right Val.
func (t *Tree) ParseFromRPN(desc string) error {
	// Used to access desc
	ptr := 0
	// When the description begins, it's as if we had just seen a left.
	lastSeen := LEFT
	t.Root = NewNode("", nil, t.BF, nil)
	currNode := t.Root

	// Read the description
	for ; ptr < len(desc); ptr++ {
		switch desc[ptr] {
		case '(':
			// LEFT
			// Error condition
			if lastSeen != RIGHT && lastSeen != OP {
				err := errors.New("Syntax error at index ptr = " + strconv.Itoa(ptr) + ": unexpected '('")
				return err
			}
			// New child
			child := NewNode("", currNode, t.BF, nil)
			currNode.AddChild(child)
			currNode = child
			// Update lastSeen
			lastSeen = LEFT

		case ')':
			// RIGHT
			// Error condition
			if lastSeen != VAL && lastSeen != RIGHT {
				err := errors.New("Syntax error at index ptr = " + strconv.Itoa(ptr) + ": unexpected ')'")
				return err
			}
			if currNode.IsRoot() {
				err := errors.New("Syntax error at index ptr = " + strconv.Itoa(ptr) + ": unmatched ')'")
				return err
			}
			// Go back to parent
			currNode = currNode.Parent
			// Update lastSeen
			lastSeen = RIGHT

		case '+':
			// OP: addition
			// Error condition
			if lastSeen != LEFT {
				err := errors.New("Syntax error at index ptr = " + strconv.Itoa(ptr) + ": unexpected '+'")
				return err
			}
			// Set the Add action
			currNode.SetAction(t.Add)
			// Update lastSeen
			lastSeen = OP

		case '*':
			// OP: multiplication
			// Error condition
			if lastSeen != LEFT {
				err := errors.New("Syntax error at index ptr = " + strconv.Itoa(ptr) + ": unexpected '*'")
				return err
			}
			// Set the Mul action
			currNode.SetAction(t.Mul)
			// Update lastSeen
			lastSeen = OP

		case 'R':
			// OP: rotation
			// Error condition
			if lastSeen != LEFT {
				err := errors.New("Syntax error at index ptr = " + strconv.Itoa(ptr) + ": unexpected 'R'")
				return err
			}
			// Set the Rot action
			currNode.SetAction(t.Rot)
			// Update lastSeen
			lastSeen = OP

		case 'v':
			// VAL
			// Error condition
			if lastSeen != LEFT {
				err := errors.New("Syntax error at index ptr = " + strconv.Itoa(ptr) + ": unexpected 'v'")
				return err
			}
			// Extract the name, set it in currNode, and set the Get action
			name, err := extractName(desc[ptr:])
			if err != nil {
				err = errors.New("Could not extract variable name from index ptr = " + strconv.Itoa(ptr) + ": " + err.Error())
				return err
			}
			currNode.SetVal(name)
			currNode.SetAction(t.Get)
			// Adjust the pointer
			ptr += len(name)
			ptr-- // Compensate the ++ of the for loop
			// Update lastSeen
			lastSeen = VAL

		default:
			err := errors.New("Syntax error at index ptr = " + strconv.Itoa(ptr) + ": unknown symbol " + string(desc[ptr]))
			return err
		}
	}

	return nil
}

// Extracts the variable name from the beginning of desc.
func extractName(desc string) (string, error) {
	ptr := 0 // Used to access desc

	// Check that first character is 'v'
	if desc[ptr] != 'v' {
		err := errors.New("Syntax error in variable name at position ptr = " + strconv.Itoa(ptr) +
			": first part of name does not begin with 'v'")
		return "", err
	}
	ptr++
	// Check that second character is space
	if desc[ptr] != ' ' {
		err := errors.New("Syntax error in variable name at position ptr = " + strconv.Itoa(ptr) +
			": no space after 'v'")
		return "", err
	}
	ptr++
	// Fast forward as long as we don't see '@'
	for ; desc[ptr] != '@'; ptr++ {
	}
	// Check that next letter is '@'
	if desc[ptr] != '@' {
		err := errors.New("Syntax error in variable name at position ptr = " + strconv.Itoa(ptr) +
			": second part of name does not begin with '@'")
		return "", err
	}
	ptr++
	// Fast forward as long as we see digits
	for ; unicode.IsDigit(rune(desc[ptr])); ptr++ {
	}

	// Do a copy
	name := make([]uint8, ptr)
	copy(name, desc[:ptr])

	return string(name), nil
}
