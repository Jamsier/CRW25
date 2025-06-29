#!/bin/bash

cleanup() {
    echo "use Ctrl+C to stop"
    exit 0
}
trap cleanup SIGINT


python3 /usr/local/flexric/xApp/python3/near-rt-ric/custom-xapp/LSTM_model/lstm_inference.py
