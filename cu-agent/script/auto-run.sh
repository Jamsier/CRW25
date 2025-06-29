#!/bin/bash

cleanup() {
    echo "use Ctrl+C to stop the record"
    kill $pid1 2>/dev/null
    wait $pid1 2>/dev/null
    exit 0
}
trap cleanup SIGINT

python3 cu-agent/script/ue-recoder.py &
python3 cu-agent/script/sniff-write.py &
pid1=$!

while true; do
    sleep 1
    python3 cu-agent/pcap/strip_gtp.py
    gradle --no-daemon -Pcmdargs=cu-agent/pcap/stripped-gtp/:cu-agent/pcap/flow-data/ runcmd
    # clear
done

kill $pid1 2>/dev/null
wait $pid1 2>/dev/null