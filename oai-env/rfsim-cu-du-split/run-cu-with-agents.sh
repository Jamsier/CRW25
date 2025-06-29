#!/bin/bash

docker compose up oai-cu -d
sleep 5s

docker compose up traffic-capture e2-agent -d

docker logs -f traffic-capture