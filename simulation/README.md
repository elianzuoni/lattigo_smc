# Simulation

This package defines simulations for the protocols, as well as for the evaluation of a specific 3-party circuit.
The Onet-related coding patterns are taken from the [cothority_template](https://github.com/dedis/cothority_template). 

Simulations allow to benchmark the execution times, and can be deployed on localhost, Mininet, and Deterlab.

## Workflow

Following is a brief description of how Onet simulations work in general, together with some details on what the specific simulations implemented here do.

### Configuration files 

The configuration files are stored in the [`runconfigs`](runconfigs) directory.

A configuration file defines a series of test cases.  
- The first part of the file is written in [toml](https://github.com/toml-lang/toml) and provides the parameters common to all test cases.  
In these simulations, it notably contains the name of the simulation and the number of rounds (how many times the same test case is repeated, to have several measures).  
- The second part of the file (separated from the first one by a blank line) is written in CSV and provides the missing parameters for each test case:
it begins with a line stating the names of the parameters, then each line defines a new test case by listing values for those parameters.  
In these simulations, it contains parameters like the number of parties and the BFV parameter set (through the index `ParamsIdx` in the array of default parameter sets).

A test case, in summary, is defined by the parameters specified in the first part of the file, together with the parameters specified in a line of the second part.


### Roles 

There are three different kinds of nodes that play different roles when executing a simulation:

- Launcher node: your computer. It is the node from which the simulation is launched, which sets up the (possibly remote) simulated nodes.
- Simulated nodes: the nodes in the system. They are the ones that actually execute the simulation. 
- Root node: Among the simulated nodes, the root is the specific one which "takes the initiative" (clarified later).

### Methods

The methods to implement for a simulation are:

- Factory: initialises some basic fields in the simulation structure given a string representation of the test case.  
- `Setup`: Only called on a dummy simulation instance at the launcher node. Its purpose is to output a `SimulationConfig` structure (containing network information on the various hosts) and, optionally, 
to write some files in the provided `dir` directory. Both will be made available to all simulated nodes.  
In the protocol simulations, this method randomly picks the public input once and for all (it will be the same for all the rounds), marshals it and writes it into a file in the `dir` directory.
- `Node`: Called at each simulated node (the working directory is a copy of the `dir` directory), taking as input the `SimulationConfig` output by the `Setup` method.  
In the protocol simulations, it reads the public input from a file in the working directory.
- `Run`: Only called at the root; this is where the body of the simulation is written.  
In protocol simulations, this method launches the protocol many times (indicated by the number of rounds) with the same public input, timing each execution and then outputting the average.  
In the circuit simulation, this method evaluates the same 3-party circuit many times (indicated by the number of rounds). Each time, it stores random inputs in the system, then sends an `EvalCircuitQuery`, 
then evaluates the circuit locally on the clear-text inputs, then retrieves the remote result and compares the two for correctness. The execution time is only measured for the `EvalCircuitQuery`.

Each file has an `init` function which binds a simulation name (indicated in the configuation file) to a simulation factory (defined in the file).

### Run sequence

The run sequence of a simulation, for each test case, is:

1) The launcher node calls the constructor to get a dummy simulation instance.
2) The launcher node calls `Setup` on the dummy simulation instance.
3) The launcher node sets up the simulated nodes, and sends them the test case, the `SimulationConfig`, and the content of the `dir` directory.
4) Every simulated node calls the constructor to get its own simulation instance.
5) Every simulated node calls `Node` on its simulation instance.
6) The root node calls `Run` on its simulation instance (after every simulated node has returned from calling `Node`).

## Running the simulations

This package is actually a `main` package (the `main` function is in [simul.go](simul.go)), so that it can be built into a `simulation` executable.  
The executable's usage is: 

`./simulation -platform $platform -debug-color "$cfg"`

with

- `$cfg`: the configuration file. Since it contains the simulation name, which the `init` function has bound to a specific simulation factory, it automatically indicates which simulation to run.
- `$platform`: the platform you want to test on. Can be `localhost`, `mininet`, or `deterlab`.

As of the last version, all the simulations can be deployed remotely (Mininet or Deterlab): the protocol simulations used to have global variables for the public input, but they have been replaced by a file written in the `dir` directory.

You can use [`run_simulations.sh`](run_simulations.sh) to run all the simulations in a row.
