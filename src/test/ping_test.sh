#!/bin/bash

TARGET_IP="192.168.5.133"

echo "脚本 PID: $$"

while true; do
    ping -c 1 $TARGET_IP > /dev/null

    FD_COUNT=$(lsof -p $$ | wc -l)
    echo "打开的文件描述符数目: $FD_COUNT"

    sleep 1
done
