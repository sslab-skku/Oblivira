#!/bin/sh

docker rm uni-resolver-web driver-did-ion -f
docker rmi tests-uni-resolver-web tests-driver-did-ion -f

docker compose up
