# Simulation

This package defines simulations for the 8 protocols, as well as for the evaluation of a specific 3-party circuit.
The Onet-related coding patterns are taken from the [cothority_template](https://github.com/dedis/cothority_template). 

Simulations allow to benchmark the execution times, and can be deployed on localhost, Mininet, and Deterlab.

## Configuration files 

The configuration files are stored in the [`runconfigs`](runconfigs) directory.

A configuration file defines a series of test cases.  
The first part of the file is written in [toml](https://github.com/toml-lang/toml) and provides the parameters common to all test cases. It contains the name of the simulation.  
The second part of the file (separated from the first one by a blank line) is written in CSV and provides the missing parameters for each test case:
it begins with a line stating the (comma-separated) names of the parameters, then each line defines a new test case by listing (comma-separated) values for those parameters.  
A test case, in summary, is defined by the parameters specified in the first part of the file, together with the parameters specified in a line of the second part.

## Workflow

### Roles 

There are three different kinds of nodes that play different roles when executing a simulation:

- Launcher node: your computer. It is the node from which the simulation is launched, which sets up the (possibly remote) simulated nodes.
- Simulated nodes: the nodes in the system. They are the ones that actually execute the simulation. 
- Root node: Among the simulated nodes, the root is the specific one which "takes the initiative" (clarified later).

### Methods

The methods to write for a simulation are:

- Factory: initialises some basic fields in the simulation structure given a string representation of the test case.  
- `Setup`: Only called on a dummy simulation instance at the launcher node. Its purpose is to output a `SimulationConfig` structure (containing network information on the various hosts) and, optionally, 
to write anything it wants in the provided `dir` directory (in protocol simulations, it is used to write a file containing the common input).  
The directory `dir` is made visible to all the simulated nodes (it is the working directory in which they are run); the `SimulationConfig`is also sent out to all the nodes.
- `Node`: Called at each simulated node (whose working directory is a copy of the `dir` directory), taking as input the `SimulationConfig` output by the `Setup` method.  
Completely sets up the simulated nodes with all the needed parameters (including the common input, which is read from a file, for protocol simulations).
- `Run`: Only called at the root. This is where the body of the simulation is written: for protocol simulations, this is where the protocol is launched; for the circuit simulation, this is where the `EvalCircuitQuery` is issued.

Each file has an `init` function which binds a simulation name (indicated in the configuation file) to a simulation factory (defined in the file).

### Pipeline

The pipeline of a simulation, for each test case, is:

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

As of the last version, all the simulations can be deployed remotely (Mininet or Deterlab): the protocol simulations used to have global variables for the common input, but they have been replaced by a file written in the `dir` directory.

You can use [`run_simulations.sh`](run_simulations.sh) to run all the simulations in a row.
