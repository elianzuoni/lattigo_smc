#! /bin/bash
parties=3

if (($# == 1));then
parties=$1
fi

echo -e "Creating configs for $parties parties"
i=0
for (( i=0; i<$parties; i++ ));do
port=$((2000+$i*10))
echo -e "Creating config of lattigo$i at localhost:$port"

echo "localhost:$port
lattigo:$i
$(pwd)/config
" | ./app server setup

cd config
mv private.toml private$i.toml
mv public.toml public$i.toml
cd ..

done

cat config/public*.toml > server.toml

echo -e "Setup done"