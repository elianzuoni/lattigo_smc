# Simulation
A simulation of a protocol is done to check for performance and correctness over a network. For more details on simulation from onet see the [cothority_template](https://github.com/dedis/cothority_template). 

You can use the `run_simulations.sh` to run all the simulations in a row.
If running Simulations individually, make use of the flag `testing.Short` to make the quick tests faster. 

In `runconfigs`, there are the configurations files for a protocol
## Configurations 
- key_gen : specify the parameter index of `bfv.DefaultParamters` with `ParamsIdx`. Other parameters are the number of `Host` & `Servers`, I use the same to have one host per server. 
- key_switch,refresh_config, relin_key_config & public_key_switch : same as key_gen 
- rotation_key_config : specify the `rotType` (`bfv.Rotation`) and the value `K`. 

## Simulation 
A simulation has different step : 
1) `init` : register the simulation for Onet here 
2) `NewSimulation` : decode the config file here. You can make use of the parameters of the configuration. 
3) `Setup` : Creates the tree that will be used for the network. 
4) `Node` : Initialize the paramters for the protocol. 
5) `Run` : Run the simulation. You can make use of different round amounts to have more than one sample. 

## simul.go 
You can build the simul.go and run it. 
`./simulation -platform $platform -debug-color "$toml"`
- `$toml` : the config file of the protocol you want to test 
- `$platform` : the platform you want to test on. If you want to test locally use localhost. For more details again check cothority_template. 