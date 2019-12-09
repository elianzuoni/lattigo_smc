package protocols

var AssignParametersBeforeStart = true
var test = true

//Test has a variable test used when you want to test so the protocols sends the result back to the root so you
//can compare the value computed.
func Test() bool {
	return test
}

//TurnOffTest used to turn off the test in a call. Can be used when testing
func TurnOffTest() {
	test = false
}
