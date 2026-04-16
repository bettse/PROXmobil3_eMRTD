#!/bin/bash -x
cd "$(dirname "$0")"
stty -F /dev/ttymxc1 115200 cs8 -cstopb -parenb
systemd-run -p StandardOutput=tty -p TTYPath=/dev/ttymxc1 -d bin/emrtd
