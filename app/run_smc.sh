#! /bin/bash

parties=3

if (($# == 1));then
parties=$1
fi

echo -e "Running lattigo instances in different terminals (parties $parties) "

for (( i=0; i<$parties; i++ ));do

xterm -T "Lattigo$i" -n "Lattigo$i" -e ./app server --config=config/private$i.toml &

done


echo -e "Done servers are running..."