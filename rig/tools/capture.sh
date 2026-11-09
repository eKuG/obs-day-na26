#!/usr/bin/env bash
# Full rehearsal from a clean slate; writes the deck's backup evidence into rig/evidence/:
#   reset -> warm up -> learn -> calm detect + shots -> incident -> incident detect + shots -> demo_facts.json
set -uo pipefail
cd "$(dirname "$0")/.."
EV=evidence; mkdir -p "$EV"
scene() { cat > /tmp/threatsig-scene.json; node tools/shots.js /tmp/threatsig-scene.json 2>&1 | sed 's/^/    /'; }
G='http://localhost:3300/d/threat-signals/threat-signals?orgId=1&kiosk&theme=light&from=now-10m&to=now&refresh=10s'

echo "== reset"; make reset >/dev/null 2>&1; echo "   warming up 150s"; sleep 150
python3 detect.py check | tail -12
echo "== learn"; python3 detect.py learn | tee "$EV/learn.txt"
echo "== detect (calm)"; python3 detect.py detect | tee "$EV/detect-calm.txt"
scene <<JSON
[{"goto": "$G", "wait": 9000}, {"shot": "01-calm-dashboard.png"}]
JSON

echo "== incident"; make incident >/dev/null 2>&1; sleep 50
echo "== detect (incident)"; python3 detect.py detect | tee "$EV/detect-incident.txt"
PID=$(python3 -c 'import detect; print(detect.owners().get("4444", ("", ""))[1])')
echo "   rogue pid: $PID"
python3 - "$PID" <<'PY' > "$EV/demo_facts.json"
import json, sys, detect
pid = sys.argv[1]
flows = detect.inbound()
peer, bps = next(((a, b) for (p, a), b in flows.items() if p == "4444"), ("", 0))
cores, funcs = detect.profile(pid)
top = next(iter(funcs.items()), ("", 0))
print(json.dumps({"pid": pid, "peer": peer, "bps": round(bps), "cores": round(cores, 2),
                  "top": top[0], "share": round(100 * top[1], 1), "svc": detect.owners()["4444"][0]}, indent=2))
PY
cat "$EV/demo_facts.json"
scene <<JSON
[{"goto": "$G&var-pid=$PID", "wait": 10000}, {"shot": "02-incident-dashboard.png"},
 {"goto": "$G&var-pid=$PID&viewPanel=5", "wait": 9000},
 {"clickSel": "button[aria-label='Expand all groups']", "after": 1500},
 {"shot": "04-flamegraph.png"}]
JSON
python3 detect.py check | tail -3
echo "== done; incident left running"
