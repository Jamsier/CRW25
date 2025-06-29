#!/bin/bash

cleanup() {
    echo "use Ctrl+C to stop the record"
    exit 0
}
trap cleanup SIGINT


while true; do
    sleep 1
    echo "Fetching malicious IPs from the servern..."
    cp /tmp/malicious_ip.json /tmp/cu-agent/ip_blacklist.json
done
