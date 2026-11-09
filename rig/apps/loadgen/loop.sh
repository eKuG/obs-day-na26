#!/bin/sh
# Normal customers: ~5 req/s against the shop.
while true; do wget -q -O- "$TARGET" >/dev/null 2>&1; sleep 0.2; done
