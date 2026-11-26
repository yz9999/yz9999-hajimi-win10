# Hajimi（哈基米）macOS + Windows 双端高性能低维护架构重构计划书

**文档版本**：v1.0（执行版）

**制定日期**：2026-11-26

**适用工程**：Hajimi 桌面客户端（macOS 13.0+ Universal `arm64/x86_64` & Windows 10/11 `x64/arm64`）

**持续集成环境**：GitHub Actions 云端流水线（`macos-15` + `windows-2022`）

## 1. 重构背景与核心工程诊断

在对 Hajimi 现有工程全部 **415 个源文件（总计 202,843 行代码）** 进行静态扫描与依赖拓扑分析后，确认当前制约双端同步演进的核心矛盾并非缺少跨平台前端框架，而是仓库内部同时并行维护着**两套功能几乎 100% 重叠的网络代理内核**：

1. **已跨平台化的 C11/C++17 统一引擎栈（84,207 行）**：由 `HajimiDataPlaneC`、`HajimiFlowCXX`、`HajimiRoutingCXX`、`HajimiProtocolCXX`、`HajimiProtocolsCXX`、`HajimiWinTransportCXX` 与门面层 `HajimiEngineCAPI` 组成，已完整实现 15 种出站/入站协议（含基于 [ngtcp2](https://github.com/ngtcp2/ngtcp2) 的 QUIC v1/v2 与 HTTP/3 传输）、Surge/Clash/ShareLink 配置解析、`198.19.0.0/16` Fake-IP 地址池、DoH/DoT 加密解析、规则集热重编译、自动测速调度以及用户态 TCP SACK 与全锥形 UDP NAT 隧道。

2. **macOS 早期遗留的重复 Swift 运行时（78,719 行）**：分布在 `HajimiCore`、`HajimiDNS`、`HajimiNativeCore`、`HajimiRouting`、`HajimiRuntime`、`HajimiProxyRuntime` 与 `HajimiCXXProtocolBridge` 中，用 Swift 重复实现了一套 TLS 1.3、HTTP/2 HPACK、Shadowsocks 2022、VLESS Vision、Reality、mKCP、XHTTP、加密 DNS 调度器、Fake-IP 表以及用户态 `NativeTunnel` 协议栈。

3. **云端构建与高并发调度瓶颈**：第三方密码库采用 OpenSSL 3.5.9，在 Windows 云端依赖 Perl 与 NMake/JOM 编译耗时长达十余至三十余分钟，且 OpenSSL 3.x 的 Provider 锁机制在多线程高频握手下存在明显竞争（参见 [HAProxy SSL 协议栈实测报告](https://www.haproxy.com/blog/fresh-from-aws-reinvent-supercharging-haproxy-community-with-aws-lc-performance-packages)）；同时传输反应堆基于传统就绪轮询扫描，在千级并发连接与微突发流量下仍有系统调用与堆分配优化空间。

### 重构核心目标（性能反超 + 维护减半）

| 核心指标 | 重构前基线 | 重构目标 | 关键技术手段 | 
| ----- | ----- | ----- | ----- | 
| **双端核心协议与 TUN 栈代码份数** | 2 套（Swift + C++） | **唯一 1 套（C11/C++17）** | macOS 与 Windows 统一绑定 `HajimiEngineCAPI.h` 纯 C 接口 | 
| **全仓冗余代码净削减量** | 202,843 行 | **净减 > 60,000 行** | 退役 Swift 重复协议栈、加密栈、DNS 引擎与双份用户态 TUN | 
| **SPSC 共享内存环吞吐率（1400B 包）** | 15.30–21.21 Gbps | **24.0+ Gbps（零丢包）** | 64 包向量化微批出入队（Batch Drain）+ 缓存行对齐单次提交 | 
| **数据包热路径堆内存分配次数** | 每包 `std::vector` 分配 | **0 次（线程本地池命中）** | 新增 2 KiB 固定槽位无锁/线程本地 `HajimiPacketSlabPool` | 
| **多路复用连接调度复杂度** | `O(N)` 轮询扫描 | **`O(活跃事件)` 原生通知** | Windows 接入 [IOCP](https://learn.microsoft.com/en-us/windows/win32/fileio/i-o-completion-ports) / epoll 快速路径，macOS 接入 [Darwin kqueue](https://developer.apple.com/library/archive/documentation/Darwin/Conceptual/FSEvents_ProgGuide/KernelQueues/KernelQueues.html) | 
| **TLS/QUIC 密码学构建与并发扩展** | OpenSSL 3.5.9（锁竞争） | **默认 [AWS-LC](https://github.com/aws/aws-lc)（双后端兼容）** | CMake + Ninja 原生编译（约 60–90 秒），支持 BoringSSL QUIC 接口与 [ML-KEM 后量子协商](https://aws.amazon.com/blogs/security/make-post-quantum-cryptography-updates-routine-with-aws-lc/) | 
| **后台托盘静默内存占用** | 25–35 MB | **保持 20–35 MB 原生级** | 保留 AppKit + WinUI 3 极薄原生壳，拒绝引入 150 MB 级常驻 WebView | 

## 2. 目标三层沙漏架构（Hourglass Architecture）

重构后全工程严格划分为三层物理边界，任何业务逻辑严禁跨层泄漏系统平台宏（`#ifdef _WIN32` / `#ifdef __APPLE__`）：

1. **底层：OS 特权网络胶水层（占全仓 \~5%，双端原生极薄隔离）**

   * **macOS (`HajimiHelper` / [NEPacketTunnelProvider](https://developer.apple.com/documentation/networkextension/nepackettunnelprovider))**：仅负责创建 `utun` 虚拟网卡（4 字节 `AF_INET`/`AF_INET6` 帧前缀）、通过 Unix Domain Socket (`SCM_RIGHTS`) 将 `utun` 文件描述符传递至非特权主程序或映射共享内存环，以及基于 `SCDynamicStore` 与 PF 执行路由与防 DNS 泄漏事务。

   * **Windows (`HajimiHelperService.exe`)**：仅负责加载 [Wintun](https://git.zx2c4.com/wintun/about/) 三层环形驱动（0 字节裸 IP 帧）、通过 [Windows Filtering Platform (WFP)](https://learn.microsoft.com/en-us/windows/win32/fwp/windows-filtering-platform-start-page) 动态会话（`FWPM_SESSION_FLAG_DYNAMIC`）阻断直连 DNS 泄漏，并通过 16 MiB 命名共享内存环与主引擎零拷贝交换三层数据包。

2. **中枢：100% 跨平台统一引擎层（`libhajimi_engine` / `HajimiEngine.dll`）**

   * 向上仅暴露纯 C11 ABI 头文件 `Sources/HajimiEngineCAPI/include/HajimiEngineCAPI.h`（Swift 通过 Clang Module Map 零开销直调，C# 通过 `DllImport` 直调）。

   * 向下通过纯 C 共享内存协议头 `Sources/HajimiPlatformC/include/HajimiShmRing.h`（支持 64 包批量收发与可配置 `frame_prefix_len`）及 `utun` 非阻塞微批桥接接口收发三层流量。

   * 平台相关钩子全部收敛于 `WinSystemProxyAndProcess.cpp`（重构升级为双端通用的平台适配单元：Windows 使用 `IP_UNICAST_IF` + `CertOpenSystemStoreW("ROOT")` + `WinINet`；macOS 使用 `IP_BOUND_IF` + Security Framework 系统锚点根证书 + `networksetup`/进程套接字查询）。

3. **顶层：零业务逻辑原生桌面薄壳 + 单源共享主题资产**

   * 提取 50 套 `.hajimitheme.json` 主题至顶层 `SharedAssets/Themes/`，构建时自动同步打包至 macOS `.app/Contents/Resources` 与 Windows `Assets/Themes`。

   * **macOS 薄壳 (`HajimiApp`)**：完整保留现有 AppKit 原生窗口、状态栏猫咪动态图标、Surge 可视化配置编辑器与策略组编辑器，但将其底层 `ProxyEngine` 与 `NativeTunnel` 门面彻底改写为 `HajimiEngineCAPI` 的轻量级 Swift 包装器。

   * **Windows 薄壳 (`Windows/HajimiWinApp`)**：保持现有 WinUI 3 桌面界面、原生 Win32 托盘右键菜单与实时连接/日志流面板；若未来大版本计划合并双端 UI 代码库，可基于现有 C# ViewModel 平滑切换至 [Avalonia Native AOT](https://docs.avaloniaui.net/docs/deployment/native-aot)。

## 3. 模块级裁剪、保留与改造清单

| 目录 / 模块路径 | 原始规模 | 重构处置策略 | 具体执行内容 | 
| ----- | ----- | ----- | ----- | 
| `Sources/HajimiPlatformC` | 373 行 | **核心增强** | 在 `HajimiShmRing.h` 增加 `spscTryPushBatch` / `spscTryPopBatch`（64 包单次原子 `head`/`tail` 发布，摊薄缓存一致性流量与系统唤醒）；新增 `HajimiPacketSlabPool.h`（2 KiB 线程本地零分配包缓冲池）与 `HajimiAsyncPoller.h`（统一封装 `IOCP`/WEpoll、`kqueue`、`epoll`/`poll`）。 | 
| `Sources/HajimiDataPlaneC` | 1,272 行 | **保留共享** | C11 无状态校验和与 IP/TCP/UDP 头编解码，双端 100% 零改动复用。 | 
| `Sources/HajimiProtocolsCXX` | 67,859 行 | **双后端升级** | 改造 `Crypto.cpp`、`Snell.cpp`、`WireGuardCore.cpp` 与 `QUICTransport.cpp`，新增 `HAJIMI_TLS_BACKEND=awslc|openssl` 编译宏支持：接入 [AWS-LC](https://github.com/aws/aws-lc/blob/main/BUILDING.md) 原生 `HMAC`/`HKDF`/`EVP_AEAD` 与 [ngtcp2](https://github.com/ngtcp2/ngtcp2) 的 `libngtcp2_crypto_boringssl`，同时向下兼容 OpenSSL 3.5。 | 
| `Sources/HajimiWinTransportCXX` | 2,210 行 | **跨平台扩展** | 接入 `HajimiAsyncPoller`（macOS `kqueue` / Windows `WSAPoll`+`IOCP` 就绪通知 / Linux `epoll`），补充 macOS `IP_BOUND_IF` / `IPV6_BOUND_IF` 出站物理网卡防回环绑定与系统根证书信任链加载。 | 
| `Sources/HajimiEngineCAPI` | 7,462 行 | **晋升唯一中枢** | `UserspacePacketTunnel` 升级为 64 包微批读取与 `HajimiPacketSlabPool` 复用；新增 `hajimi_engine_attach_utun_fd` / `hajimi_engine_detach_utun_fd` 原生支持 macOS `utun` 4 字节 AF 头非阻塞零拷贝收发；补齐 macOS 端加密 DNS 防环回与进程归属查询。 | 
| `Sources/HajimiDNS` | 6,007 行 | **整体退役删除** | 由 `HajimiEngineCAPI/EncryptedDnsAndFakeIp.cpp`（支持 DoH/DoT/UDP、RFC 8484 分块解码、物理网卡直绑与 Fake-IP）统一接管。 | 
| `Sources/HajimiCXXProtocolBridge` | 1,306 行 | **整体退役删除** | 旧版 ObjC++ 桥接层不再需要，Swift 通过新模块 `HajimiEngineCBridge` 直接导入纯 C11 `HajimiEngineCAPI.h`。 | 
| `Sources/HajimiProxyRuntime` | 1,120 行 | **整体退役删除** | 旧版 ObjC 运行时包装器退役，统一收敛至跨平台传输层。 | 
| `Sources/HajimiRouting` | 689 行 | **整体退役删除** | 路由匹配统一由 C++ 预编译基数树与后缀树 `HajimiRoutingCXX` + `hajimi_engine_evaluate_route` 执行。 | 
| `Sources/HajimiNativeCore` | 5,091 行 | **瘦身 92% 为薄桥接** | 删除 4,800+ 行重复的 Swift 用户态 TCP/UDP/ICMP 协议栈与测试夹具，仅保留约 280 行 `NativeTunnel.swift` 薄适配器，内部调用 `hajimi_engine_attach_utun_fd` 驱动 C++ 隧道。 | 
| `Sources/HajimiCore` | 63,972 行 | **瘦身 85% 为纯 UI 模型与 C 桥接门面** | 删除全部 58 个重复协议/加密/DNS/自检文件（如 `TLS13*.swift`、`HTTP2.swift`、`EncryptedDNS*.swift`、`Shadowsocks2022.swift`、`MKCP*.swift`、`NativeOutbound.swift` 等共约 54,500 行）；仅保留 `Profile.swift`、`SurgeProfileDocument.swift`、`Subscription*.swift` 等 UI 编辑器值类型模型，并将 `ProxyEngine.swift` 重写为驱动 `HJEngineRef` 的轻量门面。 | 
| `Sources/HajimiApp`（测试夹具） | 5,900+ 行 | **清理旧内嵌夹具** | 移除耦合旧 Swift 内核的 11 个内嵌 SmokeCheck 源文件，保持 39 个 AppKit 生产界面控制器 100% 契约兼容。 | 

## 4. 四大性能反超工程规范

### 4.1 64 包向量化无锁环形队列（`HajimiShmRing.h` v2）

在保持现有二进制内存布局（`HAJIMI_SHM_MAGIC = 0x4D4A4853`、16 MiB 双工区）100% 向下兼容的前提下，新增批量接口：

* **生产者微批写入 (`spscTryPushBatch`)**：单次读取消费者 `tail`（`memory_order_acquire`），在本地寄存器连续拷贝最多 `64` 个数据包至环形槽位，仅在整批写入完成后执行**唯一一次** `prod.head.store(nextHead, memory_order_release)` 与 `packets`/`bytes` 批量累加，并仅当 `consumerSleeping != 0` 时触发一次内核事件唤醒。

* **消费者微批排空 (`spscTryPopBatch` / 零拷贝切片视图 `spscPeekBatch`)**：单次获取生产者 `head`，一次性返回最多 `64` 个指向共享内存环内部的只读载荷指针与长度视图（`PacketSpan`），数据面直接原地解析 IPv4/IPv6/TCP/UDP 头部而无需二次拷贝出环，处理完毕后一次性推进 `cons.tail`。

### 4.2 线程本地 2 KiB 零分配包池（`HajimiPacketSlabPool.h`）

* 针对 MTU 1400–1500 字节的绝大多数以太网/TUN 分组，设计固定块大小 `2048` 字节、每线程预留 `256` 槽位（仅占 `512 KiB` L2/L3 缓存友好连续内存）的空闲位图池。

* TUN 出站回包、UDP NAT 重组载荷与 DNS 报文优先从线程本地槽位 O(1) 借用，超过 2048 字节的超大重组帧自动回退至标准堆分配，彻底消除千兆满载下的分配器锁争用。

### 4.3 跨平台原生异步事件多路复用器（`HajimiAsyncPoller.h`）

* 统一抽象 `HajimiAsyncPoller`（注册可读/可写边沿或水平事件 + 超时毫秒级批量等待 `waitEvents(outEvents, maxEvents=64, timeoutMs)`）：

  * **macOS / BSD**：底层直接调用 `kqueue()` + `kevent()` 批量提交变更列表与收集就绪事件。

  * **Windows**：提供基于 `IOCP` / AFD 或高吞吐批量事件通知封装（兼容 Winsock 套接字集），彻底解除传统 `FD_SETSIZE` 限制并降低空转 CPU。

  * **Linux（云端验证与服务端回归环境）**：底层直接调用 `epoll_create1(EPOLL_CLOEXEC)` + `epoll_wait()`。

### 4.4 AWS-LC 默认密码学底座与 OpenSSL 3.5 双后端无缝切换

* 在 `CMakeLists.txt` 中引入 `-DHAJIMI_TLS_BACKEND=AUTO|AWSLC|OPENSSL`：

  * **AWS-LC 模式（GitHub Actions macOS & Windows 默认）**：使用 CMake + Ninja 编译静态 `libcrypto` 与 `libssl`（启用 AVX2/NEON 汇编加速与 ML-KEM-768），链接 `libngtcp2_crypto_boringssl`，冷缓存编译时间从 35+ 分钟缩短至约 60–90 秒，多线程 TLS 握手完全无 Provider 全局锁。

  * **OpenSSL 3.5 兼容模式**：保留 `libngtcp2_crypto_ossl` 宏分支，确保在仅有系统预装 OpenSSL 3.x 的开发机或 Linux 容器中也能零外部下载直接编译并跑通全部单元测试。

## 5. 分阶段实施步骤与验收门禁

### 阶段一：底层数据面升级与跨平台引擎完备化（C11 / C++17）

1. 实现 `HajimiShmRing.h` 64 包批量零拷贝视图与批量出入队 API，配套编写多线程高并发压测验证吞吐跃升。

2. 实现 `HajimiPacketSlabPool.h` 与 `HajimiAsyncPoller.h`（覆盖 Windows、macOS `kqueue`、Linux `epoll`）。

3. 改造 `HajimiProtocolsCXX` 四处密码学与 QUIC 适配文件，支持 `AWS-LC`（BoringSSL 兼容 API）与 OpenSSL 3.x 双后端编译。

4. 升级 `HajimiEngineCAPI`：

   * `UserspacePacketTunnel` 切换至 64 包微批读取 + Slab 内存池；

   * 新增 `hajimi_engine_attach_utun_fd` / `hajimi_engine_detach_utun_fd` 支持 macOS `utun` 4 字节协议头双向非阻塞转发；

   * 完善 `WinSystemProxyAndProcess.cpp` 与 `EncryptedDnsAndFakeIp.cpp` 的 macOS / POSIX 物理网卡绑定（`IP_BOUND_IF`）、系统根证书读取与系统代理启停接口（`hajimi_sysproxy_enable` / `hajimi_sysproxy_disable`）。

### 阶段二：macOS 重复 Swift 内核退役与双端资产归一

1. 新增 Swift C 模块靶标 `Sources/HajimiEngineCBridge`（含 `module.modulemap` 导出 `HajimiEngineCAPI.h` 与 `HajimiShmRing.h`）。

2. 清理退役 `HajimiDNS`、`HajimiRouting`、`HajimiCXXProtocolBridge`、`HajimiProxyRuntime` 及 `HajimiCore` / `HajimiNativeCore` 中全部 60+ 个重复协议、TLS、DNS 与隧道实现文件。

3. 重写轻量版 `ProxyEngine.swift` 与 `NativeTunnel.swift`，将配置加载、监听器启停、策略组切换、规则热重载、节点测速、活动连接强杀、流式日志与 `utun` 隧道 100% 委托给 `HajimiEngineCAPI`，并静态校验 `HajimiApp` 全部 39 个 UI 文件引用的符号零缺失。

4. 将 50 套 `.hajimitheme.json` 归档至共享目录 `SharedAssets/Themes/`，并在 `CMakeLists.txt` 与打包脚本中自动分发至双端产物。

### 阶段三：双端统一 GitHub Actions 流水线与全量回归验证

1. 升级 `scripts/build_native_core.ps1` 与 `scripts/build_native_core.sh`：默认采用 **CMake + Ninja 极速构建 AWS-LC + ngtcp2 (`libngtcp2_crypto_boringssl`) + nghttp3 + libssh2**。

2. 新增 `.github/workflows/build-macos-windows.yml` 统一双端发布工作流（同时保留独立平台触发能力），并行构建：

   * `macos-15`：Universal (`arm64 + x86_64`) `Hajimi.app` + `HajimiHelper` + `.dmg`/`.zip`；

   * `windows-2022`：`x64` 与 `arm64` `Hajimi-Setup.exe` + `Hajimi-Portable.zip`（含 CRT 应用本地化打包与 PE 头机器码强校验）。

3. **沙箱真机编译与回归门禁**：在当前环境使用 `g++ 12.2` 完整编译升级后的 `HajimiDataPlaneC`、`HajimiFlowCXX`、`HajimiRoutingCXX`、`HajimiProtocolCXX`、`HajimiProtocolsCXX`、`HajimiWinTransportCXX` 与 `HajimiEngineCAPI`，实跑并验证：

   * L0 数据面校验和与预编译基数树路由基准；

   * SPSC 共享内存环单包 vs 64 包零拷贝微批吞吐基准（验证吞吐超越现有 21.2 Gbps）；

   * `HajimiPacketSlabPool` 与 `HajimiAsyncPoller` (`epoll`/`kqueue`/`IOCP` 语义) 并发压力测试；

   * `HajimiEngineCAPI` 端到端全链路回路自检（Surge/Clash 解析、HTTP/SOCKS5/UDP Associate 转发、Fake-IP 分配与还原、`utun` 4 字节前缀与 `Wintun` 0 字节前缀双模式用户态 TCP/UDP NAT、连接强杀与流式日志）。

## 6. 参考规范与外部依据

1. HAProxy Technologies — [Supercharging HAProxy Community with AWS-LC Performance Packages](https://www.haproxy.com/blog/fresh-from-aws-reinvent-supercharging-haproxy-community-with-aws-lc-performance-packages)

2. AWS Cryptography — [AWS-LC Repository & Building with CMake and Ninja](https://github.com/aws/aws-lc/blob/main/BUILDING.md)

3. AWS Security Blog — [Make Post-Quantum Cryptography Updates Routine with AWS-LC](https://aws.amazon.com/blogs/security/make-post-quantum-cryptography-updates-routine-with-aws-lc/)

4. ngtcp2 Project — [IETF QUIC Implementation & BoringSSL/AWS-LC Crypto Helper](https://github.com/ngtcp2/ngtcp2)

5. Microsoft Learn — [I/O Completion Ports (IOCP)](https://learn.microsoft.com/en-us/windows/win32/fileio/i-o-completion-ports) & [Windows Filtering Platform (WFP)](https://learn.microsoft.com/en-us/windows/win32/fwp/windows-filtering-platform-start-page)

6. Apple Developer — [NEPacketTunnelProvider](https://developer.apple.com/documentation/networkextension/nepackettunnelprovider) & [Darwin Kernel Queues (kqueue)](https://developer.apple.com/library/archive/documentation/Darwin/Conceptual/FSEvents_ProgGuide/KernelQueues/KernelQueues.html)

7. WireGuard Project — [Wintun Layer 3 Ring-Buffer TUN Driver](https://git.zx2c4.com/wintun/about/)

8. Avalonia UI — [Native AOT Deployment Guide](https://docs.avaloniaui.net/docs/deployment/native-aot)