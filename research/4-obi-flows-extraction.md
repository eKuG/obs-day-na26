# Section 4a-d: what eBPF lets us extract (research notes, 2026-11-08; OBI HEAD 3d08323, profiler HEAD e8a5026)

## A) OBI network flows
- OBI v1.0.0 released 2026-10-30 (first stable; rc.1 Oct 7, rc.2 Oct 16, v0.15.2 Oct 16). Began as Grafana Beyla. Kernel 5.8+ (RHEL 4.18 backports), BTF required, amd64/arm64.
- Two capture sources (network.source / OTEL_EBPF_NETWORK_SOURCE):
  - socket_filter (DEFAULT): SEC("socket/filter") on raw AF_PACKET/SOCK_RAW/ETH_P_ALL socket (pkg/internal/netolly/ebpf/sock_tracer.go:106) — every frame on every iface, coexists with Cilium.
  - tc: SEC("tc_ingress")/SEC("tc_egress") per interface; not with Cilium. OTEL_EBPF_BPF_TC_BACKEND=tc|tcx|auto; tcx on 6.6+.
- In-kernel (bpf/netolly/flows.c, flows_sock.c, flow.h): parse eth->IPv4/6->TCP/UDP; IPv4 as ::ffff-mapped IPv6. Key flow_id = {src_ip, dst_ip, if_index, eth_protocol, src_port, dst_port, transport_protocol}. Value flow_metrics = {bytes, packets, start/end_mono_time_ns, OR-ed TCP flags, iface_direction, initiator, errno}. Hash map aggregated_flows; on -E2BIG/-EBUSY single-packet record -> ringbuf direct_flows. Userspace flush every cache_active_timeout 5s or cache_max_flows 5000. Optional 1-in-N sampling. Programs never drop/modify (TC_ACT_UNSPEC).
- Direction: first packet SYN->EGRESS, SYN+ACK->INGRESS in flow_directions map, deleted on FIN/RST; fallback guess_ports. initiator = SRC/DST. iface.direction relative to capture iface.
- Dedup across ifaces (flow/deduper.go, from netobserv-ebpf-agent): key w/ IfIndex zeroed, first iface wins, LRU expiry 2x timeout; forwarded flows drop IfIndex/direction.
- Metrics (2026 names): obi.network.flow.bytes (feature network; Prom obi_network_flow_bytes_total), obi.network.flow.packets, obi.network.inter.zone.bytes (experimental, k8s). TCP stats (bpf/statsolly): obi.stat.tcp.rtt, obi.stat.tcp.failed.connections, obi.stat.tcp.retransmits, obi.stat.tcp.io — hooks kprobe tcp_sendmsg/tcp_cleanup_rbuf/tcp_close, tp sock/inet_sock_set_state, tcp/tcp_destroy_sock, raw_tp tcp_retransmit_skb/tcp_send_reset/tcp_receive_reset. No beyla.* names remain.
- Attributes default ON: direction (request/response/unknown), k8s.cluster.name, k8s.src/dst.namespace, k8s.src/dst.owner.name, k8s.src/dst.owner.type; + src/dst.cidr if network.cidrs; country/asn if geoip. Hidden by default (cardinality): src.address, dst.address, src.port, dst.port, client.port, server.port, src.name/dst.name (reverse DNS — OBI snoops DNS responses with XDP program bpf/rdns/rdns_xdp.c), k8s.src/dst.name, .type, .node.ip/name, src/dst.zone, iface, iface.direction, transport, network.type, network.protocol.name, obi.ip; service.name/namespace, service.peer.name/namespace. Owner types: replicaset, deployment, statefulset, daemonset, job, cronjob, node. attributes.select REPLACES default list.
- L7 decoded (v1.0): HTTP/1.x+HTTPS, HTTP/2, gRPC, Kafka, NATS, MQTT, Memcached, SunRPC/NFS, JSON-RPC, GraphQL (server); AMQP 1.0, DNS (client); PostgreSQL, MySQL, MSSQL, Redis (client+server); MongoDB, Couchbase, Aerospike, Elasticsearch, OpenSearch, AWS S3/SQS/SNS, GenAI APIs (OpenAI/Anthropic/Gemini) (client). RED/spans: http.server|client.request.duration, rpc.*, db.*, messaging.*, gen_ai.*, spans, span/service-graph metrics.
- TLS without keys: uprobes/uretprobes on libssl SSL_read/_ex, SSL_write/_ex/_ex2, SSL_free, SSL_set_bio, SSL_shutdown, libcrypto BIO_write (bpf/generictracer/libssl.c); Go crypto/tls uprobe cryptoTlsRead/Write; Java via bundled agent. Plaintext captured at library API.

## B) Ports/sockets/packets — hook -> what -> security meaning
| XDP (driver, pre-skb) | raw frame eth/IP/L4 per packet | OBI rDNS snoop; Cilium prefilter | DNS to odd domains; floods |
| TC/tcx (skb) | 5-tuple, ifindex, mark, bpf_skb_cgroup_id, wire bytes | OBI tc flows + traceparent; Cilium policy | pod->pod unexpected ports (lateral movement) |
| socket filter (AF_PACKET) | every frame all ifaces | OBI default flows | same, CNI-agnostic |
| sock_ops (cgroup) | TCP_CONNECT_CB, ACTIVE/PASSIVE_ESTABLISHED_CB, TCP_LISTEN_CB, RTT_CB, STATE_CB, RETRANS_CB; srtt_us, total_retrans, bytes_acked; bpf_store_hdr_opt | OBI 1 sockops + 14 sk_msg (tpinjector) | NEW LISTENING PORT; beaconing RTT/retrans |
| kprobes/tp | lifecycle: tcpconnect = kprobe tcp_v4/v6_connect; tcpaccept = kretprobe inet_csk_accept; tcplife/tcpstates = sock:inet_sock_set_state (4.16+); tcpretrans = tcp_retransmit_skb; tcptop = fentry tcp_sendmsg/recvmsg | OBI 36 distinct kernel targets incl tcp_connect, tcp_close, sys_accept4, sys_bind, sys_connect, udp_sendmsg, unix_stream_* | outbound to never-seen IP; port scan = many SYN_SENT->CLOSE no data; new bind() |
| bpf_iter | enumerate existing sockets (ss) | OBI 4 iter programs (iter_tcp.c backfill) | inventory of pre-existing listeners |
| cgroup/connect4, sendmsg | per-cgroup egress decision | Cilium socket-LB/policy | egress allow-list enforcement |

## C) Tracking / workload identity
- Local pid->pod: OBI reads /proc/<pid>/cgroup, regex 64-hex container ID (cri-containerd-<id>.scope, /kubepods/.../<id>, /k8s.io/<id>, docker) (pkg/internal/helpers/container/container.go); Pod informer: container ID -> Pod -> TopOwner (ReplicaSet->Deployment...) -> k8s.deployment.name, k8s.pod.name, k8s.container.name, service.name. Unknown cgroup => host process.
- Remote IP->workload: flow decorator store.ObjectMetaByIP(ip) on informer map keyed by IPs of Pods, Services, Nodes (pkg/kube/store.go) -> k8s.{src,dst}.name/namespace/type/owner.*/node.*; service.peer.name. Cache miss => attrs omitted. Each OBI pod runs informers or shared k8s-cache gRPC; resync 30m.
- Profiles join same key: profiler parses /proc/<PID>/cgroup (process/process.go), emits container.id + process.pid; Collector k8sattributes pod_association container.id adds pod/ns/deployment. Same cgroup path -> same 64-hex ID in both tools => profiles and flows meet on container.id -> pod -> owner. Helpers: bpf_get_current_pid_tgid, bpf_get_current_cgroup_id, bpf_skb_cgroup_id.
- Cilium: identity = uint32 from labels not IPs; reserved 1-255, well-known 100-115 (kube-dns=102), cluster-local 256-65535; ipcache map 512k IP->identity; CT 512k TCP/256k UDP; policy 16k/endpoint. Hubble flows carry identity + verdict.
- Limits: hostNetwork pods resolve to Node; SNAT/DNAT hide pod IP depending on hook (veth sees pod IPs, NIC sees node IP) (unverified OBI specifics); nodes w/o OBI seen one-sided; profiler ceiling 1% CPU / 250 MB.

## D) Logs enriched with traces
- Context propagation: ebpf.context_propagation / OTEL_EBPF_BPF_CONTEXT_PROPAGATION = all | headers | tcp | headers,tcp; default OFF; ip deprecated. sk_msg programs (bpf/tpinjector, obi_packet_extender) rewrite outgoing socket data to insert traceparent (HTTP/1 header; HPACK for h2/gRPC; tcp = TCP options). Incoming parse needs kernel 5.17+. Go: bpf_probe_write_user writes header into process memory pre-TLS (5.14+, CAP_SYS_ADMIN, lockdown none). TLS injection OBI->OBI only; L7 proxies break it.
- OBI log enrichment (trace-log correlation): probes on ksys_write, do_writev, tty_write, pipe_write rewrite app's stdout/stderr write IN PLACE — JSON gets trace_id/span_id, plain text gets key=value prefix/suffix. OBI does NOT export logs. Config v2 extensions.obi.correlation.log_trace_annotation (off by default, standalone only). Kernel 6.0+, bpffs, no lockdown. Only while span active on handling thread; first 8 KiB per write; buffered stdout (.NET, Python w/o PYTHONUNBUFFERED) unsupported.
- v0.15.2: pinned traces_ctx_v1 map off by default; ebpf.populate_trace_context: true re-enables trace<->profile correlation (from search).
- Rest = standard OTel: log record TraceId/SpanId/TraceFlags; SDK appenders; Collector k8sattributes joins on k8s.pod.ip/container.id.

## E) Numbers
1. OBI v1.0.0 — 30 Oct 2026, 9 days before talk.
2. 521 BPF program sections in bpf/ at HEAD: 182 uprobe + 19 uretprobe, 51 kprobe + 10 kretprobe, 14 sk_msg, 7 tp, 3 raw_tp, 4 socket, 4 iter, 2 xdp, 2 usdt, 1 tc_ingress, 1 tc_egress, 1 sockops; 36 distinct kernel hook targets (grep incl. bpf/tests).
3. Overhead (Beyla docs, 75 req/s OTel demo Kind): 0.05% CPU self, 0.5% all apps, 1.2% CPU / 120 MB with flows, "500 ns per request".
4. Flow defaults: 7-field key, 5000-flow cache, 5 s flush; 8 of ~35 attrs on by default.
5. Cilium: ipcache 512k, CT 512k/256k, policy 16k/endpoint, Hubble buffer 4095 flows/node.
6. bcc tcptop ~13% of one CPU at 100k TCP send/recv per second — why in-kernel aggregation matters.

## F) Sources
opentelemetry.io/docs/zero-code/obi/ (+ /network/, /network/config/, /metrics/, /distributed-traces/, /trace-log-correlation/, /configure/metrics-traces-attributes/, /configure/tune-performance/, /setup/kubernetes/); opentelemetry.io/blog/2026/obi-v1-release/; OBI releases; OBI source paths above; profiler README + process/process.go; grafana pyroscope ebpf-profiler docs; archive.grafana.com beyla v3.33 performance; docs.cilium.io identity/maps/intro; cilium numericidentity.go; bcc tools tcpconnect/tcpaccept/tcptop; brendangregg tcp-tracepoints 2018; docs.ebpf.io BPF_PROG_TYPE_SOCK_OPS; opentelemetry.io logs concepts.
