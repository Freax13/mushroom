#!/bin/sh
set -ex
export PATH=/bin:/usr/bin
cp /dev/input /input.c
/usr/bin/gcc -static /input.c -o /output
cat /output >> /dev/output
