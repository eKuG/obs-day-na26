# Auto Deriving Threat Signals from OTel CPU Profiles & OBI Network Flows

Demo rig for the Observability Day talk at KubeCon + CloudNativeCon North America 2026 (Salt Lake City, Nov 9, 2026).
Slides: [`deck/kubecon-na-2026-ebpf-threat-signals.pdf`](deck/kubecon-na-2026-ebpf-threat-signals.pdf).

Two signals many teams already collect for observability, **network flows** and **CPU profiles**, both produced by eBPF with no code in the app, quietly encode a security picture. They join on one key, the **host PID**:

```
unknown traffic on :4444          OBI network flow (socket filter)
        │  who answers on :4444?    OBI process discovery: service.instance.id = <host>:<pid>
        ▼
      PID 37194
        │  what is it running?      OTel eBPF profiler, samples for that pid
        ▼
   grind_nonce  100%  ← never seen in this workload
```

`detect.py` learns a baseline (ports, peers, hot functions), then reports anything new and follows the PID. No rule names a port, a binary or a function.

## Run it

Needs Docker with a Linux kernel that has BTF (5.8+): Docker Desktop on macOS or Windows (its Linux VM is what eBPF attaches to), or any recent Linux host. All images are public; nothing is built.

```sh
cd rig
make up          # shop (:8080) + customers, OBI 1.0, eBPF profiler, Collector, Prometheus, Pyroscope, Grafana
# wait ~3 minutes for flows, process discovery and the first profiles
make learn       # baseline while calm: ports 8080, peers 172.30.0.20, the shop's hot functions
make check       # preflight: every line OK, then READY
make detect      # "nothing new on shop"

make incident    # drops /tmp/.cache.py into the shop container: listens on :4444, burns a core in grind_nonce,
                 # and an unknown client (172.30.0.66) starts polling it
# wait ~30 s
make detect      # NEW PORT + NEW PEER shop:4444 <- 172.30.0.66, served by 'cache', host pid N, 1 core, grind_nonce 100%
make calm        # undo the incident
make down        # stop everything, volumes included
```

Measured from a clean state: the flow on :4444 appears after ~11 s; port → PID and the profile hot path after ~27 s.

| URL | What |
|---|---|
| http://localhost:3300/d/threat-signals/threat-signals?orgId=1&kiosk | the dashboard: flows per port, who talks to the shop, port → PID, CPU per process, flamegraph for the PID picked in the top-left dropdown |
| http://localhost:9090 | Prometheus (OBI flows and request metrics) |
| http://localhost:4040 | Pyroscope (profiles, one series per `<exe>:<pid>`) |

`make ports` and `make who` print the raw view (bytes per port, and which process answers each port) without Grafana.

The "attacker" is a simulation: a pure-Python loop with an obvious name, and no real coin or payload ([`rig/apps/shop/rogue.py`](rig/apps/shop/rogue.py)).

## Layout

- `rig/docker-compose.yaml`: the stack. The rig uses the `172.30.0.0/24` bridge subnet; change it if that collides on your machine.
- `rig/obi/config.yaml`: OBI discovers any process with a port in 1024–65535, keeps addresses and ports on flows, and names the CIDRs. **The interesting file.**
- `rig/profiler/config.yaml`: 20 Hz, and `service.name = <exe>:<pid>` so one PID is one profile series.
- `rig/detect.py`: `learn` / `detect` / `check`, standard-library Python, about 200 lines.
- `rig/grafana/dashboards/threat-signals.json`: the dashboard.
- `rig/tools/capture.sh`: full rehearsal that re-captures `rig/evidence/` (needs `npm install` in `rig/tools` and Google Chrome; the Chrome path in `shots.js` is the macOS one).
- `rig/evidence/`: screenshots and detector output from a rehearsal run.
- `research/`: the facts and sources behind the eBPF, probes, OBI and Falco/Calico/Cilium/OTel slides.

## Things that bit us

- **Python 3.15 isn't supported by the eBPF profiler yet** (it supports 3.6–3.14). `python:3-slim` resolved to 3.15 and the profiles had no Python frames, so the shop is pinned to `python:3.12-slim`.
- **OBI hides addresses and ports on flows by default**, to keep cardinality down. Without `attributes.select` you get namespaces and owners only.
- **The profiler distribution (`otel/opentelemetry-collector-ebpf-profiler:0.164.0`) has no `filter` or `batch` processor for profiles.** Keep the pipeline to `transform`.
- **Pyroscope drops `process.pid` and `container.id` as labels**, so the PID has to live in `service.name`.
- **OBI's `service.instance.id` is `<hostname>:<host pid>`.** That is the join key with the profiler on a VM. On Kubernetes, go one level up: container id → pod → owner, via the Collector's `k8sattributes`.
- **Port → PID here comes from OBI's request metrics**, so the listener must speak a protocol OBI parses (HTTP here). A raw TCP listener would need a socket → PID lookup.
- **OBI runs in the host network namespace** (`network_mode: host`) so its socket filter sees every container's traffic on the bridge. Use `source: socket_filter` rather than `tc` if Cilium owns TC on the node.
- A busy loop that only runs when polled is nearly invisible to a 20 Hz profiler. A real miner runs all the time, so the simulated one runs in a background thread.
