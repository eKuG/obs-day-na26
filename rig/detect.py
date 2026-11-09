#!/usr/bin/env python3
"""Auto-derive threat signals from two eBPF signals. No rules, only a baseline.

  python3 detect.py learn    snapshot what is normal for the workload: ports, peers, hot functions per port
  python3 detect.py detect   diff now against the snapshot; for anything new, follow the PID:
                             port -> process (OBI) -> functions (eBPF profiler)
  python3 detect.py check    preflight: is every piece of the rig up and producing data?

Data: OBI network flows + OBI process discovery in Prometheus; eBPF profiler samples in Pyroscope.
Standard library only.
"""
import json
import os
import subprocess
import sys
import urllib.parse
import urllib.request

PROM = "http://localhost:9090"
PYRO = "http://localhost:4040"
GRAFANA = "http://localhost:3300"
WORKLOAD = "shop"  # OBI cidr name of the box we defend (network.cidrs in obi/config.yaml)
CPU = "process_cpu:cpu:nanoseconds:cpu:nanoseconds"
BASELINE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "baseline.json")
WINDOW_S = 60
# ponytail: fixed thresholds; a function is "hot" at >=20% of a process that uses >=0.1 cores. Tune per fleet.
HOT_SHARE, HOT_CORES = 0.20, 0.10

TTY = sys.stdout.isatty()
RED, BOLD, DIM, OFF = ("\033[31m", "\033[1m", "\033[2m", "\033[0m") if TTY else ("", "", "", "")


def get(url, timeout=10):
    return json.load(urllib.request.urlopen(url, timeout=timeout))


def prom(query):
    return get(f"{PROM}/api/v1/query?" + urllib.parse.urlencode({"query": query}))["data"]["result"]


def inbound():
    """(server port, peer address) -> bytes/s flowing INTO the workload. Source: OBI network flows."""
    rows = prom(
        "sum by (server_port, src_address) (rate(obi_network_flow_bytes_total"
        f'{{dst_cidr="{WORKLOAD}", direction="request"}}[1m])) > 0'
    )
    return {(r["metric"]["server_port"], r["metric"]["src_address"]): float(r["value"][1]) for r in rows}


def owners():
    """server port -> (service name, host pid). Source: OBI process discovery, service.instance.id = <host>:<pid>."""
    rows = prom(
        "sum by (server_port, service_name, service_instance_id) "
        "(rate(http_server_request_duration_seconds_count[1m])) > 0"
    )
    return {
        r["metric"]["server_port"]: (r["metric"]["service_name"], r["metric"]["service_instance_id"].rsplit(":", 1)[1])
        for r in rows
    }


def profile(pid):
    """(cores, {function: share of self CPU}) for one host pid over the last minute. Source: eBPF profiler."""
    req = urllib.request.Request(
        f"{PYRO}/querier.v1.QuerierService/LabelValues",
        data=json.dumps({"name": "service_name"}).encode(),
        headers={"Content-Type": "application/json"},
    )
    services = json.load(urllib.request.urlopen(req, timeout=10)).get("names", [])
    svc = next((s for s in services if s.endswith(f":{pid}")), None)  # profiler sets service.name = <exe>:<pid>
    if not svc:
        return 0.0, {}
    q = urllib.parse.urlencode(
        {"query": f'{CPU}{{service_name="{svc}"}}', "from": f"now-{WINDOW_S}s", "until": "now", "format": "json"}
    )
    fb = get(f"{PYRO}/pyroscope/render?{q}")["flamebearer"]
    self_ns = {}
    for level in fb["levels"]:
        for i in range(0, len(level), 4):  # one node = [offset, total, self, name index]
            name = fb["names"][level[i + 3]]
            self_ns[name] = self_ns.get(name, 0) + level[i + 2]
    total = sum(self_ns.values()) or 1
    funcs = {n: v / total for n, v in sorted(self_ns.items(), key=lambda kv: -kv[1]) if v / total >= 0.01}
    return fb["numTicks"] / 1e9 / WINDOW_S, funcs


def learn():
    flows, own = inbound(), owners()
    if not flows:
        sys.exit("no flows into the workload yet; wait a minute after `make up` and retry")
    base = {"ports": sorted({p for p, _ in flows}), "peers": sorted({a for _, a in flows}), "functions": {}}
    for port in base["ports"]:
        if port in own:
            _, funcs = profile(own[port][1])
            base["functions"][port] = sorted(funcs)
    with open(BASELINE, "w") as f:
        json.dump(base, f, indent=2)
    print(f"{BOLD}baseline for {WORKLOAD}{OFF}")
    print(f"  ports  {', '.join(base['ports'])}")
    print(f"  peers  {', '.join(base['peers'])}")
    for port, fns in base["functions"].items():
        svc, pid = own[port]
        print(f"  :{port} served by '{svc}' pid {pid}, functions: {', '.join(fns[:6]) or '(idle)'}")
    print(f"{DIM}saved {BASELINE}{OFF}")


def detect():
    if not os.path.exists(BASELINE):
        sys.exit("no baseline yet: run `make learn` while the workload is calm")
    with open(BASELINE) as f:
        base = json.load(f)
    known_funcs = {fn for fns in base["functions"].values() for fn in fns}
    own, findings = owners(), 0

    # 1. network side: a port or a peer the workload never had
    for (port, peer), bps in sorted(inbound().items()):
        new_port, new_peer = port not in base["ports"], peer not in base["peers"]
        if not (new_port or new_peer):
            continue
        findings += 1
        what = "NEW PORT + NEW PEER" if new_port and new_peer else ("NEW PORT" if new_port else "NEW PEER")
        print(f"\n{RED}{BOLD}[{what}]{OFF} {BOLD}{WORKLOAD}:{port}  <-  {peer}{OFF}   {bps:,.0f} B/s   (OBI network flow)")
        if port not in own:
            print("   no process seen answering on this port yet; OBI picks it up on the next request")
            continue
        svc, pid = own[port]
        cores, funcs = profile(pid)
        print(f"   served by '{svc}', host pid {pid}   (OBI process discovery: service.instance.id)")
        print(f"   pid {pid} uses {cores:.2f} CPU cores   (eBPF profiler, last {WINDOW_S}s)")
        for name, share in list(funcs.items())[:4]:
            tag = f"   {RED}<- never seen in this workload{OFF}" if name not in known_funcs else ""
            print(f"   {share:6.1%}  {name}{tag}")

    # 2. profile side: a known port owner suddenly running hot code it never ran (the miner hid in a known process)
    for port, fns in base["functions"].items():
        if port not in own:
            continue
        svc, pid = own[port]
        cores, funcs = profile(pid)
        hot = [n for n, s in funcs.items() if s >= HOT_SHARE and n not in fns]
        if cores >= HOT_CORES and hot:
            findings += 1
            print(f"\n{RED}{BOLD}[NEW HOT CODE]{OFF} {BOLD}{WORKLOAD}:{port} '{svc}' pid {pid}{OFF}   {cores:.2f} cores")
            for name in hot:
                print(f"   {funcs[name]:6.1%}  {name}   {RED}<- never seen in this process{OFF}")

    if not findings:
        print(f"nothing new on {WORKLOAD}: every port, peer and hot function matches the baseline")


def check():
    ok = True

    def line(passed, label, detail=""):
        nonlocal ok
        ok &= passed
        print(f"  {'OK  ' if passed else RED + 'FAIL' + OFF}  {label}  {DIM}{detail}{OFF}")

    running = subprocess.run(
        ["docker", "ps", "--format", "{{.Names}}"], capture_output=True, text=True
    ).stdout.split()
    for name in ["shop", "loadgen", "obi", "profiler", "otelcol", "prometheus", "pyroscope", "grafana"]:
        line(name in running, f"container {name}")
    try:
        flows = inbound()
        line(any(p == "8080" for p, _ in flows), "OBI flows into shop:8080", str(sorted(flows))[:90])
        line(not any(p == "4444" for p, _ in flows), "no incident running (no traffic on 4444)")
        own = owners()
        line("8080" in own, "OBI knows who serves :8080", str(own.get("8080", "")))
        if "8080" in own:
            cores, funcs = profile(own["8080"][1])
            line(bool(funcs), f"profiler has samples for pid {own['8080'][1]}", ", ".join(list(funcs)[:3]))
    except Exception as e:  # noqa: BLE001 - preflight prints whatever broke
        line(False, "Prometheus / Pyroscope reachable", repr(e))
    try:
        line(get(f"{GRAFANA}/api/health", timeout=5).get("database") == "ok", "Grafana up", GRAFANA)
    except Exception as e:  # noqa: BLE001
        line(False, "Grafana up", repr(e))
    line(os.path.exists(BASELINE), "baseline learned", BASELINE)
    print(f"\n{'READY' if ok else RED + 'NOT READY' + OFF}")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    {"learn": learn, "detect": detect, "check": check}.get(sys.argv[1] if len(sys.argv) > 1 else "", lambda: sys.exit(__doc__))()
