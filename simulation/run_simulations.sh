#! /bin/bash

go build

for toml in runconfigs/*.toml; do

echo -e "Running configuration : $toml"
./simulation -platform localhost -debug-color "$toml"

done

echo -e "Finished running all simulations."