# Section 4e: Falco / Calico / Cilium / OTel — how each uses eBPF (research notes, 2026-11-08)

## Falco
- CNCF Graduated Feb 29 2024. Latest 0.45.2 (Oct 29 2026).
- Drivers: kernel module, legacy eBPF probe (deprecated 0.43 Jan 2026, secondary source), modern eBPF probe = default: CO-RE, bundled, needs BTF + BPF ring buffer, kernel >=5.8. 0.45: 256 KiB staging per CPU, BPF atomics (5.12+).
- Hooks (libs source, all tp_btf raw tracepoints): sys_exit dispatcher, sched_process_exec/fork/exit, sched_switch, page_fault_user/kernel, signal_deliver.
- Produces: syscall events -> userspace libsinsp state engine -> rule engine -> alerts (JSON; stdout/file/gRPC/Falcosidekick). Plugins: k8saudit, CloudTrail, Okta. "Falco does not support correlating events from different sources."
- Decision logic: userspace rule engine; kernel side only selects which syscalls (base_syscalls, 0.35+). Conditional in-kernel filtering open request (libs #1557).
- Enforce: No. Falco Talon is a separate response project.
- Numbers: default bundle = 25 stable rules (+32 incubating, +39 sandbox). Drops observed >164K events/s/CPU on 128-CPU box.

## Calico (Tigera)
- Not a CNCF project. v3.33.0 (Oct 1 2026).
- Hooks: TC on every Calico iface (netkit default on 6.7+ / TCX / legacy TC), XDP for host-endpoint doNotTrack deny-list policy, socket BPF connect-time LB (kube-proxy replacement). Policy compiled to eBPF bytecode; IP sets + conntrack + services in BPF maps. 3.31: eBPF plane programs nftables.
- Produces policy verdicts, LB. No OTel output. In-kernel decisions, enforces (drop).
- "Designed for 40GBit+"; kernel >=5.10; eBPF by default* since 3.31 (Nov 2025).

## Cilium / Hubble / Tetragon
- CNCF Graduated Oct 11 2023. Cilium 1.20.4 (Oct 23 2026); 1.19 = 10-year release.
- Hooks: XDP (DDoS drop, NodePort accel), TC ingress/egress on veth/host (L3/L4 policy, redirect), sock_ops on root cgroup + sk_msg (sockmap), cgroup connect4/6, sendmsg4/6, recvmsg4/6, getpeername4/6 = socket-level LB.
- Hubble: flows with Verdict FORWARDED/DROPPED/ERROR/AUDIT (+drop_reason_desc), L3/L4/L7 (HTTP/DNS), identities, service map. Export JSON/Prometheus. No native OTLP (unverified).
- Tetragon v1.8.0 (Oct 30 2026): hooks kprobes, fentry/fexit (>=6.1), tracepoints, raw tp, uprobes, USDT, LSM BPF. TracingPolicy CRD selectors = in-kernel filtering + actions (Sigkill/Override/Post/NoPost/TrackSock run in BPF). Default events only process_exec/exit.
- Enforces: yes (drop; kill/override).
- Benchmark: ~1M req/s at ~30% CPU on 32 procs, 100G NIC, kernel 5.10.

## OpenTelemetry (OBI + eBPF profiler + profiles)
- OBI v1.0.0 Oct 30 2026 (Beyla donated May 2025). Profiles signal public Alpha Mar 2026.
- OBI hooks (source): uprobes on runtime fns (Go net/http ServeHTTP, http2), kprobes/kretprobes (tcp_connect, sys_connect, sys_accept4, udp_sendmsg, security_socket_accept), tc_ingress/tc_egress for flows, socket filter, SOCK_OPS + SK_MSG for context propagation.
- Profiler: perf_event/native_tracer_entry sampling; default 20 samples/s per CPU. "1% CPU and 250MB memory are our upper limits."
- Produces OTLP spans, RED metrics, network flow metrics (bytes/packets, TCP RTT, retransmits), service graph, OTLP profiles. No rules, no enforcement.
- OBI kernel 5.8+ BTF; profiles need Collector >=0.148.0 + service.profilesSupport gate; profiler = `profiling` receiver in otelcol-ebpf-profiler distro.

## Matrix
| | Purpose | Hooks | Output | Kernel filtering | Enforce | OTel-native |
| Falco | runtime threat detection | tp_btf sys_exit, sched_*, page_fault_*, signal_deliver | alerts | syscall-set only; rules userspace | No | No |
| Calico | CNI + policy | TC/TCX/netkit, XDP, socket BPF | verdicts, LB | Yes | Yes (drop) | No |
| Cilium/Hubble/Tetragon | CNI + policy + obs + runtime sec | XDP, TC, sock_ops/sk_msg, cgroup; Tetragon kprobe/fentry/tp/uprobe/USDT/LSM | flows w/ verdicts, metrics, process events | Yes | Yes | No |
| OTel (OBI + profiler) | observability signals | uprobe, kprobe, TC, socket filter, sock_ops; perf_event | spans, RED, flows, profiles | No rules | No | Yes (OTLP) |

## Contrast facts
1. Falco: 25 stable rules; docs: "view the rules as examples... users also create their own custom rules".
2. Tetragon emits only exec/exit until a TracingPolicy CRD is authored.
3. OTel: OBI 1.0 + profiler produce flows/spans/profiles at 20 Hz / <1% CPU, zero rules; Profiling SIG next step = "correlation between eBPF agents, such as OBI and the Profiling Agent".
4. Hubble flows and OBI flows come from the same TC hook; same src/dst/bytes/k8s identity. Hubble adds verdict; OBI adds RTT/retransmits + OTLP.

## Sources
falco.org/docs/concepts/event-sources/kernel/ ; github.com/falcosecurity/libs driver/modern_bpf/programs/attached ; github.com/falcosecurity/rules ; falco.org/docs/troubleshooting/dropping/ ; libs #1557 ; falco-talon
docs.tigera.io/calico/latest/about/about-ebpf ; .../operations/ebpf/enabling-ebpf ; tigera.io/blog zero-trust ebpf 3.31
docs.cilium.io/en/stable/network/ebpf/intro/ ; .../kubeproxy-free/ ; .../operations/performance/benchmark/ ; hubble export ; api/v1/flow/flow.proto
tetragon.io/docs/overview/ ; .../tracing-policy/hooks/ ; .../selectors/ ; .../enforcement/
opentelemetry.io/docs/zero-code/obi/ ; opentelemetry.io/blog/2026/obi-v1-release/ ; opentelemetry.io/blog/2026/profiles-alpha/ ; github.com/open-telemetry/opentelemetry-ebpf-profiler ; elastic.co continuous-profiling-opentelemetry
Unverified: Falco legacy-probe deprecation 0.43; OTel CNCF level 2026; Hubble OTLP adapters; profiles-alpha exact date; Cilium 1.19 date.
