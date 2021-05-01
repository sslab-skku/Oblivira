#!/bin/bash

NUM_TRIAL=20
NUM_THREADS=8

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
	echo $pid
	pid_list+=($pid)
    done
    # sleep 0.1
done







