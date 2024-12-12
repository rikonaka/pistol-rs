#!/bin/bash

TARGET_IP="192.168.5.133"

echo "Script PID: $$"

while true; do
    ping -c 1 $TARGET_IP > /dev/null

    FD_COUNT=$(lsof -p $$ | wc -l)
    echo "Opened fd: $FD_COUNT"

    sleep 1
done
