#!/bin/bash

function cleanup {
    cd rfsim-cu-du-split
    docker compose down
    cd ..
    docker compose down
    exit 0
}
trap cleanup SIGINT

docker compose up mysql ims oai-udr oai-udm oai-ausf oai-nrf oai-amf oai-smf oai-upf oai-ext-dn nearRT-RIC -d
docker logs -f oai-amf
