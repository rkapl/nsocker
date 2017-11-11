#!/bin/bash
source common.sh

echo "./block_port > blocker-root.pid"
./block_port > blocker-root.pid
assert 0
echo "./block_port > blocker-failed.pid"
./block_port > blocker-failed.pid
assert 2

echo "unshare -n ../nsocker-daemon -v -p server.pid server"
unshare -n ../nsocker-daemon -v -p server.pid server
assert 0

echo "LD_PRELOAD=../libnsocker-preload.so NSOCKER_SERVER=server ./block_port > blocker-ns.pid"
LD_PRELOAD=../libnsocker-preload.so NSOCKER_SERVER=server ./block_port > blocker-ns.pid
assert 0
