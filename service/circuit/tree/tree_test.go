// Here, we misuse the CipherID struct: the field ID is unused, and the field Owner hosts the variable name.
// The functions add, get, mul and rot are here just loggers.

package tree

import (
	"fmt"
	"github.com/ldsec/lattigo/bfv"
	"go.dedis.ch/onet/v3/log"
	uuid "gopkg.in/satori/go.uuid.v1"
	"lattigo-smc/service/messages"
	"testing"
)

func getLog(name string) (messages.CipherID, error) {
	log.Lvl2("Resolving", name)
	return messages.CipherID{name, uuid.Nil}, nil
}

func addLog(id1 messages.CipherID, id2 messages.CipherID) (messages.CipherID, error) {
	log.Lvl2("Adding", id1.Owner, "and", id2.Owner)
	return messages.CipherID{"(" + id1.Owner + "+" + id2.Owner + ")", uuid.Nil}, nil
}

func mulLog(id1 messages.CipherID, id2 messages.CipherID) (messages.CipherID, error) {
	log.Lvl2("Multiplying", id1.Owner, "and", id2.Owner)
	return messages.CipherID{"(" + id1.Owner + "*" + id2.Owner + ")", uuid.Nil}, nil
}

func rotLog(id messages.CipherID, rotIdx int, k uint64) (messages.CipherID, error) {
	var rotString = ""
	switch rotIdx {
	case bfv.RotationRow:
		rotString = "R"
	case bfv.RotationLeft:
		rotString = "CL"
	case bfv.RotationRight:
		rotString = "CR"
	}
	log.Lvl2("Rotating", rotString, id.Owner, ": k =", k)
	return messages.CipherID{fmt.Sprintf("R[%s, %d](%s)", rotString, k, id.Owner), uuid.Nil}, nil
}

// Just test functionality, not error conditions.
// Evaluate (a*(b+R[R, 20](c)))*(R[CL, 1000](d)+(e+(f*g)))
func TestEvaluate(t *testing.T) {
	tree := NewBinaryTree(getLog, addLog, mulLog, rotLog)
	desc := "*(*(v a@1)(+(v b@1)(R[R, 20](v c@1))))(+(R[CL, 1000](v d@1))(+(v e@1)(*(v f@1)(v g@1))))"

	log.SetDebugVisible(3)
	err := tree.ParseFromRPN(desc)
	if err != nil {
		t.Fatal("Parse returned error:", err)
	}

	id := tree.Evaluate()
	fmt.Println(id.Owner)
}
