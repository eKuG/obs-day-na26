# Sections 1+2: eBPF intro + tools landscape (research notes, 2026-11-08)

## A) eBPF in one slide
- ebpf.io: "run sandboxed programs in a privileged context such as the operating system kernel" without changing kernel source or loading a module. Event-driven hooks (syscalls, fn entry/exit, tracepoints, network events) or anywhere via kprobes/uprobes.
- Pipeline: C/Rust -> LLVM bytecode -> verifier -> JIT -> attached. Maps share state kernel<->user (hash/array/LRU/ringbuf/stacktrace/LPM, per-CPU). Helpers = stable kernel API; kfuncs = not stable API. BTF = kernel type info; CO-RE = compile once, libbpf relocates field offsets at load.
- Verifier guarantees: loader holds capabilities; program "does not crash or otherwise harm the system"; "always runs to completion"; no uninit vars / OOB memory. Analogy: eBPF is to the kernel what JavaScript was to the browser.
- Timeline: 1992 BPF (McCanne/Jacobson, tcpdump) -> 2014 Linux 3.18 bpf() syscall -> 2015 4.1 kprobe attach -> 2016 4.8 XDP -> 2018 4.18 BTF -> 2019 5.3 bounded loops -> 2020 5.7 BPF LSM + 5.8 ring buffer -> Aug 2021 eBPF Foundation (Meta, Google, Isovalent, Microsoft, Netflix) -> Oct 2023 Cilium graduates -> Feb 2024 Falco graduates -> Nov 2024 6.12 sched_ext -> May 2025 Beyla donated -> Mar 2026 OTel Profiles public alpha -> Oct 30 2026 OBI v1.0.0. eBPF for Windows still pre-release (v1.7.0 Oct 2026).
- Why vs modules/sidecars/agents: modules = no security boundary, break across releases; eBPF = verified safety, hot-load no reboot, zero app code changes, JIT near-native. Gregg: "Instrument anything, safely, in production... 'superpowers'". Caveat: "uprobes are slow".
- Numbers: verifier 1,000,000 instructions max; stack 512 B; unprivileged 4096 insns. Cloudflare bench (6.5-rc1, getpid 117 ns baseline): empty tracepoint +15 ns, fentry +24 ns, kprobe +137 ns, uprobe ~1,670 ns. State of eBPF (LF 2024): Meta every packet since 2017; Google most DC traffic; every Android phone; Netflix 200M customers; Meta sched_ext 5% CPU gain; Cilium XDP LB at Seznam 2x throughput, 72x less CPU; kernel = 30M LOC. OTel profiler "1% CPU and 250MB memory upper limits".

## B) Use cases
- Networking: Katran (Meta XDP L4 LB; per-CPU maps lockless; Maglev table fits L1; scales with RX queues). Cilium kube-proxy replacement.
- Observability: OBI (uprobes app/TLS, kprobes socket syscalls, TC flows: bytes/packets/RTT/retransmits); OTel eBPF profiler (perf_event, whole-system, C/C++/Go/Rust/Python/Java/Node/.NET/PHP/Ruby/Perl/Erlang, no debug symbols); bpftrace one-liners.
- Security: Tetragon (in-kernel Sigkill/Override, LSM >=5.7); Falco (modern eBPF default since 0.38, legacy probe removed 0.44); KubeArmor (BPF-LSM).
- Security FROM observability signals: Pixie detect RandomX/Monero miners via CFROUND instruction counts (bpftrace); CryptoGuard (Oct 2025 preprint): eBPF miner detection at 0.06% CPU, ~85 s latency, auto-blocks pool connections; Tetragon syscall n-grams -> ML 99.75% (Sungshin 2025); "Hybrid Runtime Detection of Malicious Containers Using eBPF" (CMC 2026): network-flow + syscall fused per container beats either alone. Hubble flows -> auto-generated network policy = precedent.

## C) Tools landscape (gh latest, 2026-11-08)
| Tool | Layer | Hooks | Does | Status | CNCF |
| bcc | toolkit | k/uprobe, tp | ~100 tracing tools, compiles on host | v0.37.0 Jul 2026 | — |
| bpftrace | toolkit | k/uprobe, tp, USDT, perf | one-liner tracing language | v0.27.1 Oct 2026 | — |
| libbpf | toolkit | all | CO-RE loader | v1.8.0 Oct 2026 | — |
| cilium/ebpf (Go) | toolkit | all | pure-Go loader | v0.22.0 Jun 2026 | Cilium |
| aya (Rust) | toolkit | all | Rust both sides | v0.16.0 Oct 2026 | — |
| Cilium | networking | XDP, TC, socket/cgroup | CNI, kube-proxy replacement | 1.20.4 Oct 2026 | Graduated Oct 2023 |
| Hubble | observability | Cilium datapath | flow/service/security visibility | 1.20.4 | Cilium sub |
| Tetragon | security | kprobe/uprobe/tp/LSM/USDT | TracingPolicy, in-kernel enforcement | v1.8.0 Oct 30 2026 | Cilium sub |
| Calico eBPF | networking | TC, XDP, cgroup | iptables-free dataplane, 5.10+ | v3.33.0 Oct 2026 | — (Tigera) |
| Falco | security | syscall tp (modern_ebpf CO-RE) | rules engine | 0.45.2 Oct 2026 | Graduated Feb 2024 |
| Tracee | security | tp/kprobe/LSM/uprobe | Aqua runtime security + forensics | v0.24.1 Nov 2025 | — |
| KubeArmor | security | BPF-LSM | in-kernel policy enforcement | v1.7.6 Oct 2026 | Sandbox |
| Pixie | observability | kprobe + uprobe (TLS) | zero-instrumentation K8s telemetry | 0.14.x pre | Sandbox |
| Parca | observability | perf_event | continuous profiler | v0.30.0 Nov 2026 | — |
| OTel eBPF Profiler | observability | perf_event | whole-system profiler, Collector receiver; ex-Elastic | Alpha; Profiles alpha Mar 2026 | OTel (Graduated) |
| OBI | observability | uprobe/kprobe/TC | zero-code RED, traces, flows; ex-Beyla | v1.0.0 Oct 30 2026, kernel >=5.8 | OTel |
| Inspektor Gadget | toolkit | gadgets as OCI images | kubectl debugging | v0.58.0 Nov 2026 | Sandbox |
| Kepler | sustainability | none since 0.10 (now /proc + RAPL) | per-pod energy | v0.13.0 | Sandbox |
| Retina (MS) | observability | kprobe/tp/TC | CNI-agnostic net observability, Hubble-compatible | 1.0 Feb 2026; v1.3.1 | — |
| Odigos | observability | uprobes (Go) + SDKs | zero-code traces | ~v1.36 (unverified) | — |
| Coroot | observability | kprobe/tp/uprobe | zero-instr APM | v1.29.2 | — |
| DeepFlow | observability | kprobe/uprobe + AF_PACKET | auto distributed tracing | v7.2.3 | landscape |
| Pyroscope/Alloy | observability | perf_event (fork of OTel profiler) | profiling DB | v2.4.3 | — |
| Katran | networking | XDP | Meta L4 LB | untagged | — |
| bpfman | toolkit | loader | eBPF program manager + K8s operator | v0.6.0 Mar 2026 | Sandbox |

## D) Under-the-hood drops
1. Verifier = static symbolic execution of every path; loops forbidden (DAG) until 5.3 bounded loops; 1M budget -> termination proven by exhaustion.
2. fentry/fexit use BPF trampolines -> fentry +24 ns vs kprobe +137 ns (no int3 path). BPF LSM reuses trampoline on security hooks.
3. Maps are fds: bpf() syscall; pin to bpffs to outlive loader; per-CPU maps make Katran lock-free.
4. Ring buffer (5.8) vs perf buffer: one MPSC buffer across CPUs, ordering preserved, reserve/commit zero-copy; "outperforms perf buffer in almost all practical scenarios" (Nakryiko).
5. CO-RE: /sys/kernel/btf/vmlinux + libbpf relocations = one binary across kernels, no LLVM on host; Falco modern probe = one CO-RE object vs bcc compiling at runtime (Gregg: bcc "obsolete / special-use").

## E) Sources
ebpf.io/what-is-ebpf ; kernel bpf_design_QA ; Gregg SIGCOMM 2024 slides ; LF State of eBPF 2024 ; eBPF Foundation PR ; cloudflare/ebpf_exporter benchmark ; nakryiko.com/posts/bpf-ringbuf ; LWN 816313 (KRSI), 794934 (bounded loops) ; Katran eng blog 2018 ; opentelemetry.io/blog/2026/obi-v1-release ; opentelemetry.io/blog/2026/obi-goals ; OTel profiler README ; elastic otel-profiling-alpha ; cncf.io/projects ; falco.org/blog/falco-0-40-0, 0-44-0 ; kepler 0.10 rewrite ; Retina 1.0 ; microsoft/ebpf-for-windows ; blog.px.dev/detect-monero-miners ; CryptoGuard ; techscience CMC v86n3 ; infoq cilium-119 ; infoq pyroscope-2
Unverified: Odigos version; Elastic contribution exact date; Windows eBPF announcement date; Gregg events/s rule of thumb.
