#! /bin/bash

for i in {0..1000}
do
    echo "-------------------------------------"
    echo "Run: $i"

    ./bench-server localhost 1234 qdx
done
