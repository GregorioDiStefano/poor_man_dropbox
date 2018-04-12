#!/bin/bash
set -u -x -e 

function finish {
    rm -rf src  
    rm -rf dst
}

trap finish EXIT

mkdir src || true
mkdir dst || true

for i in {1..5}
do
    folder=$(openssl rand -hex 6)
    mkdir ./src/"$folder"
    yes "foobar" | tr '\n' '\0' | dd of=./src/"$folder"/file_"$i" count=$((4096*i))
done

./server.py dst &
sleep 1
./client.py src &
wait

diff -rq dst/src src

if [ "$?" -eq 0 ]; then
    echo "PASSED"
else
    echo "FAILED"
fi
