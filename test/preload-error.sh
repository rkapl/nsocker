#!/bin/bash
source common.sh
LD_PRELOAD=../libnsocker-preload.so NSOCKER_SERVER=server ./block_port > blocker.pid
assert 1
