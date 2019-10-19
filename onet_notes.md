# Notes on onet

## Simulation 
- Server members = nodes
- Services are run by node - used to start the protocol. 
- Node function can be used to inject info at the start of the protocol to each node from the service 


- To build you need to have the package simulation be main
- then the command is : 
	`./simulation -platform $yourplatform $tomlfile`
	where $yourplatform can be either localhost/mininet
	$tomlfile is the tomlfile used to indicate what protocol to run 


