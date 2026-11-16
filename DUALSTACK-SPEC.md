# fastp2p 双栈协议规格 v1（本次改造冻结契约）

原则：**全部加字段，缺字段=只有 IPv4**。旧客户端/旧网关看到不认识的字段必须忽略，
新客户端对旧对端永远只走 v4 路径。地址文本一律用字符串（JSON），v6 用 `inet_ntop`
规范文本，不带方括号、不带 %scope（scope 场景本期不做）。

## 1. 能力位 families（bitmap）
- bit0(1)=IPv4 可达，bit1(2)=IPv6 可达。
- 登录查询串：`...&families=<n>`（缺省=1）。网关注册帧 `6/0` 冗余 `"families":<n>`。
- 网关侧来源以观测为准：WSS 连接族是硬证据；`establish()` 把源地址按族写入
  `ip`(v4)/`ipv6`(v6) 且相应置位 families；其余字段信任客户端自报（与现有 natType 一致）。

## 2. NAT 探测（2/*）
- v6：客户端用 v6 UDP socket 向**网关的 v6 观测地址**发同样的 `2/0 null`、`2/1 {echoPort}`。
- 应答字段名不变：`IP`、`port`、`isPublicIP` —— 语义改为"观测到的源地址（任意族）"。
  旧客户端只向 v4 目标探测，永远只收到 v4 文本，兼容性不变。
- 网关 nat.c：每族独立 UDP 端口集（v6 复用同端口号 27180-27183）与 TCP（27180-27181）。
  v6 用 `IPV6_RECVPKTINFO`/`in6_pktinfo.ipi6_addr` 做应答源；link-local 场景本期不验证。

## 3. TCP 探测回显格式 probeV3
- 旧格式 `"%s:%u"`（v6 文本有歧义，禁止）；新格式：v6 用 `"[<v6>]:<port>"`，v4 不变。
- 能力协商：登录应答加 `"tcpProbeV3":1`（与 tcpProbeV2 并列）。新客户端仅在 V3 下
  做 v6 TCP 探测；解析端：若以 `[` 开头按 v6 解析。

## 4. 按族 NAT 等级上报（任务三核心）
- `6/0` 与 `6/9` 新增：`"udpNatType6":<1|2|3|4|314>`、`"tcpNatType6":<1|2|314>`、
  `"tcpNatSamples6"`、`"tcpNatDestinationIPs6"`、`"IPv6":"<文本>"`（公网观测 v6）、
  `"hasIPv6":0/1`。
- 语义与现有 v4 字段完全平行（分类算法同款，只是探测目标是网关 v6 端口集）。
- 存储：nodes 表新列 `nat6 INTEGER NOT NULL DEFAULT 314`、`tcp_nat6 INTEGER NOT NULL DEFAULT 314`、
  `tcp_nat6_samples INTEGER NOT NULL DEFAULT 0`、`tcp_nat6_ips INTEGER NOT NULL DEFAULT 0`、
  `families INTEGER NOT NULL DEFAULT 1`。迁移沿用 store.c `nat_columns()` 的
  ALTER TABLE ADD COLUMN 范式；`PRAGMA user_version` 5→6。
- API/控制台：节点 JSON 输出 `udpNatType6`、`tcpNatType6`、`families`；
  NAT 列渲染为 "UDP：v4值 / v6值"、"TCP：v4值 / v6值"（v6 为 314 且无 v6 能力时显示 "—"）。

## 5. 打洞协商（3/1 连接请求、3/2 应答）
- 新增 `"fromIP6":"<文本>"`、`"coneNatPort6":<n>`。旧客户端只读 fromIP，不受影响。
- 新客户端选择规则：`families(self)&families(peer)` 含 bit1 → **先试 v6**（v6 无 NAT 概率高），
  超时/失败自动回退 v4 同流程；仅含 bit0 → 纯 v4。同 LAN 判定按同族比较。
- 隧道内记录所用族 `t->family`，所有 sockaddr 用 storage+len。

## 6. 中继选择（5/0、5/1）
- `5/0` 新增可选 `"wantFamily":<1|2|4?>` 本期不用；客户端把 desired family 记在 app 上即可。
- 网关硬过滤：候选必须 `families(candidate) ⊇ (families(requester) & families(peer))`
  且交集非空；不满足记 `skip_family` 计数（与 skip_nat 并列，进 relay-select 日志）。
- `RELAY_RANK` 改为按"两端公共族中的选定族 f"比较 `ip_of(candidate,f)` vs `ip_of(peer,f)`；
  quality 用选定族的 NAT（v4→nat，v6→nat6）。
- `5/1` 应答新增 `"family":<1|2>` 表示网关据以选路的族；客户端按该族发起中继打洞。
- v4-only 中继绝不会被选为 v6-only 端点对的 relay（反之亦然）。

## 7. 控制面连接（客户端）
- 网关主机名解析用 `getaddrinfo(AF_UNSPEC)`；登录 URL host 为 v6 字面量时加方括号。
- 去掉 `CURLOPT_IPRESOLVE=V4`；`CURLOPT_RESOLVE` 改为每个解析结果一条（v4+v6 都钉上）。
- host 字符白名单放开 `:`（仅当是合法 IPv6 文本，安装 Token 信封本期不动）。
- `local_ip`/`ip` 扩为 46 字节并按族存两份（`ip4/ip6` 或 `addr[2]`）。

## 8. 转发/SOCKS5（数据面 v6，本期做到监听与出口双栈）
- `bind_ip` 允许 v6 文本；默认仍 `127.0.0.1`。`resolve4`→`resolve_any`。
- `TUN_OPEN.dstIP` 已是字符串：dstIP 为 v6 文本或域名时，出口用 `resolve_any`。
  出口回 `TUN_OPEN_ACK` 的 `boundIP/remoteIP` 可为 v6 文本；接收端按内容判族。
  仅当两端 families 均含 v6 时才允许产生 v6 结果（入口侧控制，旧端不受影响）。
- 本地 SOCKS5 入口：`socks.c` 支持 ATYP=4（16 字节），回包 22 字节；UDP ASSOCIATE
  中继帧双长度（v6 ATYP=4）。`test_socks.c` 的 "ATYP=4→拒绝" 断言改为 "ATYP=4→支持"，
  同步改 SOCKS5-ZH.md 能力声明（新增：需要 2.0.8+ 出口）。

## 9. NAT 等级（natLevel，参照 EasyTier 的判定原理）

映射探测只回答"锥形还是对称"。真正的 NAT1–NAT4 需要两步**入站过滤**探测：

| 探针 | 消息 | 通过的含义 |
|---|---|---|
| 换端口回包 | 客户端 `2/2 {port,nonce}` → 网关从**另一个本地端口**回 `2/2 {nonce}` | 不是端口受限 |
| 外来源回包 | 客户端 WSS `2/3 {port,nonce}` → 网关请**另一个在线节点**从自身 IP 发 `2/4 {nonce}` | 全锥 |

判定：映射对称 → 4；换端口被丢 → 3；换端口通过且外来源被丢 → 2；两者都通过 → 1；
映射锥形但无第二节点可测 → 5（控制台显示 `NAT1/2`，不猜）。`0` = 未知。

探测在登录**之后**进行（外来源需要 WSS 信令），因此不延迟 IPv4 登录时序；结果经 `6/9` 补报，
网关存 `nat_level` 列（schema 7）。`udpNatType` 保持纯映射语义不变，中继筛选与旧对端仍读它。

## 10. 明确不做（本期）
- link-local + %scope、IPv6 install-token、v6 多路径/flowlabel、`IPV6_V6ONLY` 复用策略
  （v6 监听一律 V6ONLY，与 v4 同端口并存；这是实现而非可选策略）。
- 静态包的 libwebsockets 已改为 `-DLWS_IPV6=ON`，静态网关同样支持 `--bind6`。
