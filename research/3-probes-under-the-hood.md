# Section 3: kernel/user probes — what they do and how (research notes, 2026-11-08)

## A) Attachment points
| Hook | K/U | Static/Dyn | Since | Under the hood | Overhead | Example |
| kprobe | K | dyn | BPF type 4.1 | copy probed insn, overwrite first byte w/ int3; trap -> pre_handler -> single-step copy -> post_handler. Optimized kprobe: 5-byte jmp to detour buffer (CONFIG_OPTPROBES). ftrace-based kprobes at fentry nop | kprobes.rst: int3 0.5-1.0 us, optimized 0.07-0.1 us; Cloudflare 2023: +137 ns | OBI kprobe/tcp_sendmsg |
| kretprobe | K | dyn | same | entry kprobe saves real return addr in kretprobe_instance, "replaces the return address with the address of a trampoline"; maxactive default max(10, 2*NR_CPUS), overflow = missed probes | 50-75% longer than kprobe | OBI kretprobe/sys_accept4 |
| kprobe.multi / fprobe | K | dyn | 5.18 (uprobe.multi 6.6) | on top of ftrace; attach thousands of fns fast | bpftrace 3,342 fns ~1.5 s | Tetragon/bpftrace kprobe:vfs_* |
| fentry/fexit/fmod_ret | K | dyn (BTF) | 5.5 / fmod_ret 5.7 | BPF trampoline (text_poke'd direct call via ftrace), no trap, BTF-typed args; fexit sees args+retval "no matter where the return occurs"; fmod_ret non-zero skips fn (security hooks + error-injection only) | Cloudflare +24 ns vs kprobe +137 (~5.7x) | Tetragon fentry (>=6.1) |
| tracepoint | K | static | 4.7 | TRACE_EVENT sites; disabled = nop via static keys ("branch selection basically free"); perf_event_open(PERF_TYPE_TRACEPOINT) | Cloudflare +15 ns | OBI tracepoint/sock/inet_sock_set_state |
| raw_tracepoint / tp_btf | K | static | 4.17 / 5.5 | same sites, raw u64 args, no field conversion; tp_btf = BTF-typed | raw_tp 365k vs tp 330k vs kprobe 325k lookups/s (base 381k) | Falco tp_btf/sys_exit |
| uprobe | U | dyn | 3.5 | "A special copy is made of the page... instruction replaced by a breakpoint" (int3) -> trap to kernel -> handler -> execute-out-of-line; applies to every process mapping the file | Cloudflare ~1,670 ns/call; 6.12 RCU rework 1-CPU ~3.0->3.4 M/s (~300 ns best), 80-core 3.7->10.3 M/s | OBI uprobe/libssl.so:SSL_read |
| uretprobe | U | dyn | 3.5; syscall opt 6.11 | return addr swapped for user trampoline that traps; 6.11 uretprobe syscall 10-30% faster | ~2.0 M/s 1-CPU | OBI uretprobe/SSL_write |
| USDT | U | static | uprobe-based; libbpf 0.8 | compiler emits nop + .note.stapsdt (addr, args, semaphore); uprobe at the nop; kernel bumps 2-byte semaphore on attach | "fastest uprobe kind" | bpftrace U |
| perf_event | K | sampling | 4.9 | perf_event_open SOFTWARE/HARDWARE w/ sample_freq; prog runs each sample w/ CPU register state; bpf_get_stackid/get_stack | proportional to Hz | OTel profiler perf_event/native_tracer_entry @ 20 Hz cpu-clock |
| XDP | K net | — | 4.8 | "just after receiving the packet but before allocating memory for a socket buffer"; native/offload/generic; 256 B headroom; ABORTED/DROP/PASS/TX/REDIRECT | 24 Mpps/core drop; XDP_PASS +13.3 ns | Cilium prefilter, Calico DoS, OBI rDNS |
| TC / tcx | K net | — | 4.1 / tcx 6.6 / netkit 6.7 | cls_bpf on clsact ingress+egress, direct-action; __sk_buff w/ mark/cb/hash; tcx = fd links, multi-prog | ~XDP minus skb cost | OBI tc_ingress/tc_egress |
| socket filter | K net | — | 3.19 | setsockopt(SO_ATTACH_BPF) on AF_PACKET; ingress; return = bytes to keep | tcpdump-grade | OBI default socket/filter + socket/http_filter |
| sock_ops / sk_msg / sk_skb | K net | — | 4.13 (cb flags 4.16) | cgroup-attached; callbacks ACTIVE/PASSIVE_ESTABLISHED, RTO, RETRANS, STATE; bpf_setsockopt; sockmap redirect | per-connection | OBI sockops+sk_msg (traceparent injection); Cilium redirect |
| cgroup hooks | K | — | skb/sock 4.10; sock_addr 4.17; sysctl 5.2 | cgroup_skb ingress/egress; sock_create/post_bind; connect4/6, bind, sendmsg, recvmsg, getpeername can rewrite args or block; sysctl | per-syscall | Cilium socket LB |
| BPF LSM | K | static hooks | 5.7 (KRSI) | trampoline-attached to LSM hooks (same as SELinux/AppArmor); 0 allow, error denies (-EPERM); sleepable | hook cost | Tetragon lsmhooks |
| kfuncs / struct_ops / bpf_iter | K | — | 5.13 / 5.6 / 5.8 | kfuncs BTF-exposed, no UAPI guarantee; struct_ops fills kernel ops struct (tcp_congestion_ops, sched_ext 6.12); iter walks kernel objects via seq_file | — | OBI/Falco iter/tcp, iter/task_file |

## B) What each class sees
- kprobe/uprobe: pt_regs -> PT_REGS_PARM1..5, IP, SP; kret/uret: PT_REGS_RC; any: bpf_get_current_pid_tgid/comm/cgroup_id, bpf_get_stackid/get_stack (kernel+user).
- fentry/fexit/tp_btf/LSM: BTF-typed args (struct sock *), CO-RE field reads w/o bpf_probe_read; fexit retval.
- tracepoint: event format struct; raw_tp: u64 args.
- user memory: bpf_probe_read_user[_str]; writes need bpf_probe_write_user + CAP_SYS_ADMIN.
- XDP: raw frame data..data_end, no skb; TC/socket filter/cgroup_skb: __sk_buff; sock_ops: bpf_sock_ops (state, srtt_us, snd_cwnd).
- perf_event: regs at sample + sample_period, addr.

## C) Which probes power which tools
- OBI: kprobes tcp_sendmsg/tcp_recvmsg/tcp_connect/tcp_close/sock_recvmsg/udp_sendmsg/sys_connect/security_socket_accept/wake_up_new_task/setup_new_exec; kretprobes sys_accept4/sys_clone/tcp_sendmsg; socket/http_filter (AF_PACKET, CAP_NET_RAW) protocol sniffing; uprobes Go net/http (ServeHTTP, roundTrip, readRequest, http2 framer), Go runtime (newproc1, casgstatus, chan ops), crypto/tls Read/Write (Go return probes = uprobes on ret sites); uprobes libssl SSL_read/SSL_write(_ex), libcrypto BIO_write; flows tc_ingress/tc_egress or socket/filter (default socket_filter, avoids Cilium TC conflict); TCP stats tracepoint/sock/inet_sock_set_state, raw_tracepoint/tcp_retransmit_skb|tcp_send_reset; context propagation sockops + sk_msg; rDNS xdp; iter/tcp. Kernel >=5.8 + BTF.
- OTel eBPF profiler: perf_event/native_tracer_entry on CPUClock, default 20 Hz; native unwind from .eh_frame stack deltas (Go .gopclntab), no frame pointers; tail-calls to per-interpreter unwinders (python/ruby/php/perl/hotspot/v8/dotnet/beam/luajit); max 32 tail calls; 128-frame traces; also off_cpu, sched_monitor, heap_usdt; kernel >=5.10; "1% CPU and 250MB memory upper limits".
- Falco modern_bpf: tp_btf/sys_exit dispatcher, sched_process_exec|fork|exit, sched_switch, signal_deliver, page_fault_user|kernel; sys_enter dispatcher dropped 2025-09-15 (enter tps only for TOCTOU on open*/connect); iter/task, iter/task_file; BPF ringbuf 8 MB default, 1 per 2 CPUs; CO-RE; kernel >=5.8.
- Cilium: XDP (prefilter/DDoS, NodePort native accel), TC ingress/egress on veth (L3/L4 policy), sock_ops root cgroup + sk_msg (redirects), cgroup connect/sendmsg/recvmsg socket LB.
- Tetragon: kprobes, fentry/fexit (>=6.1, no enforcement), tracepoints, raw tp, uprobes, USDT, LSM; in-kernel selectors; enforcement = override return ("only syscalls and security check functions") + SIGKILL.
- Calico eBPF: tc on each Calico iface, socket BPF connect-time LB, XDP DoS/doNotTrack.
- bpftrace: kprobe/kretprobe, uprobe/uretprobe, usdt, tracepoint, rawtracepoint, fentry/fexit, profile, interval, software, hardware, iter, watchpoint.

## D) Numbers
1. Same syscall, four probes (Cloudflare, getpid 117 ns base): tracepoint +15, fentry +24, kprobe +137, uprobe ~+1,670 ns — user probes ~100x kernel ones because every hit traps.
2. kprobes.rst: int3 kprobe ~1 us vs jump-optimized ~0.06-0.1 us (10x).
3. XDP paper: 24 Mpps/core drop vs Linux stack 4.8 Mpps raw / 1.8 with conntrack; DPDK 43.5; XDP_PASS +13.3 ns.
4. kretprobe rewrites your return address to a trampoline; maxactive overflow silently drops — fexit avoids.
5. Verifier 1M insns since 5.2 (4,096 before / unprivileged); 32 tail calls; uprobe RCU rework 6.12: 3.7->10.3 M/s; uretprobe syscall 6.11: 10-30% faster.

## E) Sources
docs.kernel.org/trace/kprobes.html ; uprobetracer.html ; LWN 499190 (uprobes) ; fprobe.html ; static-keys ; bpf/prog_lsm.html ; kernelnewbies 5.18, 6.6 ; kprobe-multi cover letter (patchew 20220222170600) ; LWN 804937 (BPF trampoline) ; uretprobe syscall pull (lkml 2407.2/00652) ; LWN 984805 (uprobe RCU) ; docs.ebpf.io program types / usdt / kfuncs / verifier ; libbpf usdt.c ; docs.cilium.io bpf progtypes, ebpf intro, kubeproxy-free ; cloudflare/ebpf_exporter benchmark README ; lkml 1604.0/04221 (samples/bpf overhead) ; XDP CoNEXT'18 paper ; xdp-paper bench01 ; OBI bpf/ ; OBI security docs ; OBI network config ; OTel profiler README, doc/internals.md, tracer/tracer.go ; falco libs modern_bpf attached ; falco.org/blog/falco-modern-bpf ; tetragon hooks + enforcement ; tigera about-ebpf ; bpftrace docs/language.md#probes ; Gregg 2015 uprobe post
Unverified: kprobes 2.6.9 date; rethook naming; why OBI uses ret-site uprobes for Go.
