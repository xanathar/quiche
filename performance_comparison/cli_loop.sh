#! /bin/bash

for i in {0..1000}
do
    echo "-------------------------------------"
    echo "Run: $i"

    ./bench-client localhost 1234 qdx

    pids=$(pgrep bench-server)
    echo "Killing $pids..."
    kill -9 $pids

    sleep 5
done
