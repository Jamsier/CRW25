#!/bin/bash

cleanup() {
    echo "use Ctrl+C to stop the record"
    exit 0
}
trap cleanup SIGINT


while true; do
    sleep 1.2
    echo "Getting indication from e2 node"
    cp /tmp/flow-data/capture-stripped.pcap_Flow.csv /tmp/measurements_data/measurements.csv
done
