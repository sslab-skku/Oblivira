#!/bin/bash

NUM_TRIAL=100
NUM_THREADS=4

pid_list=()
function sigint_handler() {
    # for pid in "${pid_list[@]}"
    # do
    # 	kill -9 $pid
    # done
    exit 1
}

trap sigint_handler SIGINT

for i in $(seq 1 $NUM_TRIAL)
do

    for thread in $(seq 1 $NUM_THREADS)
    do
	pid=$(./did-request-single.sh & echo $!)
	pid_list+=($pid)
    done
    sleep 0.1
    echo -e "\n-------------------$i th iteration----------\n"
    
done







