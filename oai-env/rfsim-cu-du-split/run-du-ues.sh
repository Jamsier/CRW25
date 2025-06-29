#!/bin/bash

docker compose up oai-du -d
sleep 10s

docker compose up oai-nr-ue -d
sleep 7s
docker exec -d rfsim5g-oai-nr-ue bash -c "ip route replace default via 10.0.0.1 dev oaitun_ue1" & # && python3 /opt/oai-nr-ue/etc/normalUser/test.py
sleep 5s

docker compose up oai-nr-ue2 -d
sleep 11s
docker exec -d rfsim5g-oai-nr-ue2 bash -c "ip route replace default via 10.0.0.1 dev oaitun_ue1" & # && python3 /opt/oai-nr-ue/etc/normalUser/test.py
sleep 5s

docker compose up oai-nr-ue3 -d
sleep 8s
docker exec -d rfsim5g-oai-nr-ue3 bash -c "ip route replace default via 10.0.0.1 dev oaitun_ue1" &  # && python3 /opt/oai-nr-ue/etc/normalUser/test.py
sleep 5s


# docker stats
# docker logs -f rfsim5g-oai-cu