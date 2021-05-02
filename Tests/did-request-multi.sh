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

start=`date +%s`
for i in $(seq 1 $NUM_TRIAL)
do

    for thread in $(seq 1 $NUM_THREADS)
    do
	pid=$(./did-request-single.sh & echo $!)
	pid_list+=($pid)
    done
    sleep 0.1
    echo -e "\n-------------------$i th iteration----------\n"

    end=`date +%s`
    runtime=$((end-start))

    if [ $runtime -gt 20 ] 
    then
	echo "\n----------Time's up---$runtime seconds elapsed----------\n"
	exit 1
    else
	echo "\n-------------------$runtime seconds elapsed----------\n"
    fi
    
done







