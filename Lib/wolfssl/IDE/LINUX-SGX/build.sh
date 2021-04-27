#!/bin/bash
echo $PWD
pushd .
cd ../..
make clean
popd
echo $PWD
make -j$(nproc) -f ./sgx_t_static.mk
