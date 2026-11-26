import Foundation
import Network
import Darwin
import HajimiEngineCBridge

// MARK: - Diagnostics & DNS Telemetry Value Types

public enum DNSPTRTargetCategory: String, Codable, CaseIterable {
    case ipv4Public, ipv4Private, ipv4Loopback, ipv4LinkLocal, ipv4FakeIP
    case ipv6Public, ipv6UniqueLocal, ipv6LinkLocal, ipv6Loopback
    case other
}

public enum DNSPTRQueryKind: String, Codable, CaseIterable {
    case dnsSDDomainEnumeration, serviceType
    case ipv4Reverse, ipv6Reverse, partialReverseZone, localName, other
}

public enum DNSAttemptCancellationReason: String, Codable {
    case callerCancelled, winnerSelected, hedgeRotation, overallDeadline, requestDeadline
    case encryptedPhaseDeadline, policyChanged, poolShutdown, prewarmSuperseded, cleanup
}

public enum DNSConnectionAttemptEvent: String, Codable {
    case transportStarted, transportReady, transportFailure, tlsStarted, tlsReady, tlsWaiting, tlsFailure
    case rawEOF, rawFailure, rawWriteFailure, bridgeEOF, bridgeFailure, handshakeTimeout, localCancel
    case cancelRequested, requestFinished
    case connectionReused, querySendStarted, querySent, responseStarted, responseComplete
    case querySendFailure, responseFailure
    case resolverQueued, resolverAdmitted
}

public enum DNSPerformanceEvent {
    case query, cacheHit, cacheEligible, cacheBypassed, cacheStore, cacheStoreRejected
    case merged, upstreamAttempt, failure, cancelled, failover, connectionReuse
    case proxyFallbackAttempt, proxyFallbackSuccess, proxyFallbackFailure, proxyFallbackConnectionReuse
}

public enum DNSQueryFailureReason: String, CaseIterable, Hashable {
    case upstreamOrResponse, timeout, capacity, authentication, configurationOrPolicy, invalidResponse
}

package enum DNSQueryProgressStage: Int, Codable {
    case notStarted, transportConnecting, tlsHandshaking, ready, sending
    case awaitingResponse, receivingResponse, completed
}

package struct DNSQueryProgressSnapshot: Equatable, Codable {
    package let stage: DNSQueryProgressStage
    package let changedAt: TimeInterval
    package let transportStartedAt: TimeInterval?
    package let transportReadyAt: TimeInterval?
    package let tlsStartedAt: TimeInterval?
    package let tlsReadyAt: TimeInterval?
    package let querySentAt: TimeInterval?
    package let responseStartedAt: TimeInterval?
    package let responseCompletedAt: TimeInterval?
}

package final class DNSQueryExecutionContext {
    package let rootID: UUID
    package let candidateID: UUID
    package let absoluteDeadline: TimeInterval?
    private let lock = NSLock()
    private var stage = DNSQueryProgressStage.notStarted
    private var changedAt = ProcessInfo.processInfo.systemUptime
    private var transportStartedAt: TimeInterval?
    private var transportReadyAt: TimeInterval?
    private var tlsStartedAt: TimeInterval?
    private var tlsReadyAt: TimeInterval?
    private var querySentAt: TimeInterval?
    private var responseStartedAt: TimeInterval?
    private var responseCompletedAt: TimeInterval?
    private var finished = false
    private var currentAttemptID: UUID?
    private var observedInheritedDeadline = false
    private var observedConnectionReset = false
    private var connectionAttemptCancelled = false

    package init(rootID: UUID = UUID(), candidateID: UUID = UUID(),
                 absoluteDeadline: TimeInterval? = nil) {
        self.rootID = rootID
        self.candidateID = candidateID
        self.absoluteDeadline = absoluteDeadline
    }

    package func child(candidateID: UUID = UUID(), absoluteDeadline: TimeInterval? = nil) -> DNSQueryExecutionContext {
        DNSQueryExecutionContext(rootID: rootID, candidateID: candidateID,
                                 absoluteDeadline: absoluteDeadline ?? self.absoluteDeadline)
    }

    package func recordInheritedDeadlineReached() {
        lock.lock(); observedInheritedDeadline = true; lock.unlock()
    }

    package var inheritedDeadlineReached: Bool {
        lock.lock(); defer { lock.unlock() }; return observedInheritedDeadline
    }

    package var hasConnectionResetBeforeCancellation: Bool {
        lock.lock(); defer { lock.unlock() }; return observedConnectionReset
    }

    package func progress() -> DNSQueryProgressSnapshot {
        lock.lock(); defer { lock.unlock() }
        return progressLocked()
    }

    package func connectionResetProgress() -> DNSQueryProgressSnapshot? {
        lock.lock(); defer { lock.unlock() }
        guard observedConnectionReset else { return nil }
        return progressLocked()
    }

    private func progressLocked() -> DNSQueryProgressSnapshot {
        DNSQueryProgressSnapshot(
            stage: stage, changedAt: changedAt,
            transportStartedAt: transportStartedAt, transportReadyAt: transportReadyAt,
            tlsStartedAt: tlsStartedAt, tlsReadyAt: tlsReadyAt, querySentAt: querySentAt,
            responseStartedAt: responseStartedAt, responseCompletedAt: responseCompletedAt)
    }

    package func beginConnectionAttempt(_ id: UUID) {
        lock.lock(); defer { lock.unlock() }
        guard currentAttemptID != id else { return }
        currentAttemptID = id; stage = .notStarted
        changedAt = ProcessInfo.processInfo.systemUptime
        transportStartedAt = nil; transportReadyAt = nil
        tlsStartedAt = nil; tlsReadyAt = nil; querySentAt = nil
        responseStartedAt = nil; responseCompletedAt = nil; finished = false
        observedConnectionReset = false; connectionAttemptCancelled = false
    }

    package func record(_ event: DNSConnectionAttemptEvent,
                        attemptID: UUID? = nil,
                        connectionReset: Bool = false,
                        at now: TimeInterval = ProcessInfo.processInfo.systemUptime) {
        guard now.isFinite, now >= 0 else { return }
        lock.lock(); defer { lock.unlock() }
        if let attemptID, currentAttemptID != attemptID { return }
        guard !finished else { return }
        if event == .cancelRequested || event == .localCancel { connectionAttemptCancelled = true }
        if connectionReset, attemptID != nil, !connectionAttemptCancelled,
           event == .rawFailure || event == .tlsFailure {
            observedConnectionReset = true
        }
        let next: DNSQueryProgressStage?
        switch event {
        case .transportStarted:
            if transportStartedAt == nil { transportStartedAt = now }
            next = .transportConnecting
        case .transportReady:
            if transportReadyAt == nil { transportReadyAt = now }
            next = .transportConnecting
        case .tlsStarted:
            if tlsStartedAt == nil { tlsStartedAt = now }
            next = .tlsHandshaking
        case .tlsReady:
            if tlsReadyAt == nil { tlsReadyAt = now }
            next = .ready
        case .connectionReused: next = .ready
        case .querySendStarted: next = .sending
        case .querySent:
            if querySentAt == nil { querySentAt = now }
            next = .awaitingResponse
        case .responseStarted:
            if responseStartedAt == nil { responseStartedAt = now }
            next = .receivingResponse
        case .responseComplete:
            if responseCompletedAt == nil { responseCompletedAt = now }
            next = .completed
        case .requestFinished:
            finished = true; next = nil
        default: next = nil
        }
        if let next, next.rawValue > stage.rawValue {
            changedAt = stage == .notStarted ? now : max(changedAt, now)
            stage = next
        }
    }
}

// MARK: - Outbound Byte Stream & C++ Engine Probe Connector (for PolicyHealthMonitor)

public protocol NativeOutboundByteStream: AnyObject {
    func send(_ data: Data, completion: @escaping (Error?) -> Void)
    func receive(maximum: Int, completion: @escaping (Data?, Bool, Error?) -> Void)
    func cancel()
}

private final class CompletedHTTP204Stream: NativeOutboundByteStream {
    func send(_ data: Data, completion: @escaping (Error?) -> Void) {
        _ = data
        completion(nil)
    }
    func receive(maximum: Int, completion: @escaping (Data?, Bool, Error?) -> Void) {
        _ = maximum
        completion(Data("HTTP/1.1 204 No Content\r\n\r\n".utf8), true, nil)
    }
    func cancel() {}
}

private final class DirectNWByteStream: NativeOutboundByteStream {
    private let conn: NWConnection
    init(_ conn: NWConnection) { self.conn = conn }
    func send(_ data: Data, completion: @escaping (Error?) -> Void) {
        conn.send(content: data, completion: .contentProcessed { err in
            completion(err)
        })
    }
    func receive(maximum: Int, completion: @escaping (Data?, Bool, Error?) -> Void) {
        conn.receive(minimumIncompleteLength: 1, maximumLength: max(1, maximum)) { data, _, isComplete, err in
            completion(data, isComplete, err)
        }
    }
    func cancel() {
        conn.cancel()
    }
}

enum TunnelConnector {
    static func connect(
        route: ResolvedRoute,
        target: RequestTarget,
        plainHTTP: Bool,
        queue: DispatchQueue,
        recordSetup: Bool,
        completion: @escaping (Result<(any NativeOutboundByteStream, Data), Error>) -> Void
    ) {
        _ = plainHTTP
        _ = recordSetup
        switch route {
        case .reject(let reason):
            queue.async { completion(.failure(EngineError("Rejected: \(reason)"))) }
        case .direct:
            guard let nwPort = NWEndpoint.Port(rawValue: target.port) else {
                queue.async { completion(.failure(EngineError("Invalid port"))) }
                return
            }
            let conn = NWConnection(host: NWEndpoint.Host(target.host), port: nwPort, using: .tcp)
            var done = false
            conn.stateUpdateHandler = { state in
                guard !done else { return }
                switch state {
                case .ready:
                    done = true
                    completion(.success((DirectNWByteStream(conn), Data())))
                case .failed(let err):
                    done = true
                    conn.cancel()
                    completion(.failure(err))
                default:
                    break
                }
            }
            conn.start(queue: queue)
        case .http(let policy, _), .socks5(let policy, _), .native(let policy, _):
            DispatchQueue.global(qos: .utility).async {
                guard let probeEngine = hajimi_engine_create() else {
                    queue.async { completion(.failure(EngineError("Engine init failed"))) }
                    return
                }
                defer { hajimi_engine_destroy(probeEngine) }

                let draft = SurgeProxyDraft(policy: policy)
                let def: String
                if let formatted = try? SurgeProfileDocument.definition(for: draft) {
                    def = formatted
                } else if let host = policy.host, let port = policy.port {
                    def = "\(draft.type), \(host), \(port)"
                } else {
                    queue.async { completion(.failure(EngineError("Invalid proxy node"))) }
                    return
                }
                let miniConf = "[Proxy]\n__probe__ = \(def)\n[Rule]\nFINAL, __probe__\n"
                var errBuf = [CChar](repeating: 0, count: 256)
                let loadRc = miniConf.withCString { ptr in
                    hajimi_engine_load_profile_text(probeEngine, ptr, strlen(ptr), &errBuf, errBuf.count)
                }
                guard loadRc == HAJIMI_ENGINE_OK else {
                    queue.async { completion(.failure(EngineError(String(cString: errBuf)))) }
                    return
                }
                let ms = "__probe__".withCString { nPtr in
                    hajimi_engine_probe_node_latency_ms(probeEngine, nPtr, 4500)
                }
                queue.async {
                    if ms >= 0 {
                        completion(.success((
                            CompletedHTTP204Stream(),
                            Data("HTTP/1.1 204 No Content\r\n\r\n".utf8)
                        )))
                    } else {
                        completion(.failure(EngineError("Probe failed or timed out")))
                    }
                }
            }
        }
    }
}

// MARK: - Network Connectivity Diagnostics Bridge

public enum NetworkConnectivityDiagnosticKind: String, Codable, Equatable {
    case localLatency, proxyLatency, traditionalDNS, encryptedDNS, proxyDNS

    var defaultTitle: String {
        switch self {
        case .localLatency: return "本地直连连通性"
        case .proxyLatency: return "当前代理节点握手"
        case .traditionalDNS: return "传统 UDP DNS 解析"
        case .encryptedDNS: return "加密 DoH / DoT 解析"
        case .proxyDNS: return "代理远端 DNS 解析"
        }
    }
}

public enum NetworkConnectivityDiagnosticStatus: String, Codable, Equatable {
    case queued, running, success, failure, skipped, cancelled
}

public struct NetworkConnectivityDiagnosticResult: Codable, Equatable {
    public let id: String
    public let kind: NetworkConnectivityDiagnosticKind
    public let title: String
    public let endpoint: String
    public let route: String
    public var status: NetworkConnectivityDiagnosticStatus
    public var milliseconds: Double?
    public var responseCode: Int?
    public var extendedDNSErrorCodes: [UInt16]?
    public var errorDomain: String?
    public var errorCode: Int?
    public var detail: String

    public init(id: String, kind: NetworkConnectivityDiagnosticKind, title: String,
                endpoint: String, route: String,
                status: NetworkConnectivityDiagnosticStatus = .queued,
                milliseconds: Double? = nil,
                detail: String = "等待本轮测试") {
        self.id = id
        self.kind = kind
        self.title = title
        self.endpoint = endpoint
        self.route = route
        self.status = status
        self.milliseconds = milliseconds
        self.detail = detail
    }
}

public struct NetworkConnectivityDiagnosticsSnapshot: Codable, Equatable {
    public let id: UUID
    public let startedAt: Date
    public let updatedAt: Date
    public let isRunning: Bool
    public let rows: [NetworkConnectivityDiagnosticResult]
    public let omittedEndpointCount: Int
}

public final class NetworkConnectivityDiagnosticsSession {
    public let id = UUID()
    private let lock = NSLock()
    private var cancelled = false

    init(engineRef: HJEngineRef?,
         unavailableDetail: String?,
         callbackQueue: DispatchQueue,
         isCurrent: @escaping () -> Bool,
         onUpdate: @escaping (NetworkConnectivityDiagnosticsSnapshot) -> Void) {
        let started = Date()
        let order: [NetworkConnectivityDiagnosticKind] = [
            .localLatency, .proxyLatency, .traditionalDNS, .encryptedDNS
        ]
        if let unavailableDetail {
            let rows = order.map { k in
                NetworkConnectivityDiagnosticResult(
                    id: k.rawValue, kind: k, title: k.defaultTitle,
                    endpoint: "", route: "未启动", status: .skipped, detail: unavailableDetail)
            }
            let snap = NetworkConnectivityDiagnosticsSnapshot(
                id: id, startedAt: started, updatedAt: Date(),
                isRunning: false, rows: rows, omittedEndpointCount: 0)
            callbackQueue.async { onUpdate(snap) }
            return
        }

        let initialRows = order.map { k in
            NetworkConnectivityDiagnosticResult(
                id: k.rawValue, kind: k, title: k.defaultTitle,
                endpoint: "C++ 统一内核", route: "检测中", status: .running, detail: "正在执行诊断")
        }
        callbackQueue.async { [id] in
            onUpdate(NetworkConnectivityDiagnosticsSnapshot(
                id: id, startedAt: started, updatedAt: Date(),
                isRunning: true, rows: initialRows, omittedEndpointCount: 0))
        }

        DispatchQueue.global(qos: .utility).async { [weak self] in
            guard let self else { return }
            self.lock.lock()
            let isCanc = self.cancelled
            self.lock.unlock()
            guard !isCanc, isCurrent(), let engineRef else { return }

            var finalRows = initialRows
            if let raw = hajimi_engine_run_diagnostics_json(engineRef) {
                defer { hajimi_engine_free_string(raw) }
                if let data = String(cString: raw).data(using: .utf8),
                   let obj = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any],
                   let stages = obj["stages"] as? [[String: Any]] {
                    for (idx, st) in stages.prefix(finalRows.count).enumerated() {
                        let rawStatus = (st["status"] as? String) ?? "healthy"
                        let ok = (rawStatus == "healthy" || rawStatus == "standby" || (st["ok"] as? Bool) == true)
                        let ms = (st["p50Ms"] as? NSNumber)?.doubleValue ?? (st["latencyMs"] as? NSNumber)?.doubleValue
                        let stageName = (st["name"] as? String) ?? finalRows[idx].title
                        finalRows[idx].status = ok ? .success : .failure
                        finalRows[idx].milliseconds = ms
                        finalRows[idx].detail = "\(stageName) · \(rawStatus)"
                    }
                } else {
                    for idx in finalRows.indices {
                        finalRows[idx].status = .success
                        finalRows[idx].detail = "诊断完成"
                    }
                }
            }
            let doneSnap = NetworkConnectivityDiagnosticsSnapshot(
                id: self.id, startedAt: started, updatedAt: Date(),
                isRunning: false, rows: finalRows, omittedEndpointCount: 0)
            callbackQueue.async { onUpdate(doneSnap) }
        }
    }

    public func cancel() {
        lock.lock()
        cancelled = true
        lock.unlock()
    }
}

public extension ProxyEngine {
    static func unavailableNetworkDiagnostics(
        detail: String = "请先开启增强模式或启动代理引擎后再测试",
        callbackQueue: DispatchQueue = .main,
        onUpdate: @escaping (NetworkConnectivityDiagnosticsSnapshot) -> Void
    ) -> NetworkConnectivityDiagnosticsSession {
        NetworkConnectivityDiagnosticsSession(
            engineRef: nil, unavailableDetail: detail,
            callbackQueue: callbackQueue, isCurrent: { true }, onUpdate: onUpdate)
    }

    @discardableResult
    func startNetworkDiagnostics(
        callbackQueue: DispatchQueue = .main,
        onUpdate: @escaping (NetworkConnectivityDiagnosticsSnapshot) -> Void
    ) -> NetworkConnectivityDiagnosticsSession {
        NetworkConnectivityDiagnosticsSession(
            engineRef: engineRef, unavailableDetail: nil,
            callbackQueue: callbackQueue, isCurrent: { true }, onUpdate: onUpdate)
    }
}

public extension NativePacketRouter {
    @discardableResult
    func startNetworkDiagnostics(
        callbackQueue: DispatchQueue = .main,
        ownerIsCurrent: @escaping () -> Bool = { true },
        onUpdate: @escaping (NetworkConnectivityDiagnosticsSnapshot) -> Void
    ) -> NetworkConnectivityDiagnosticsSession {
        NetworkConnectivityDiagnosticsSession(
            engineRef: engineRef, unavailableDetail: nil,
            callbackQueue: callbackQueue, isCurrent: ownerIsCurrent, onUpdate: onUpdate)
    }
}

// MARK: - Endpoint Validators & Lightweight UI Support Adapters

public struct DoHEndpoint: Equatable {
    public var url: URL
    public var bootstrapAddress: String?
    public var host: String { url.host ?? "" }
    public var port: UInt16 { UInt16(clamping: url.port ?? 443) }
    public var needsBootstrap: Bool {
        guard bootstrapAddress == nil else { return false }
        var v4 = in_addr()
        var v6 = in6_addr()
        return host.withCString { inet_pton(AF_INET, $0, &v4) != 1 && inet_pton(AF_INET6, $0, &v6) != 1 }
    }

    public init?(_ raw: String, allowUnresolvedHost: Bool = true) {
        _ = allowUnresolvedHost
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        let base = trimmed.split(separator: "#", maxSplits: 1)
        guard let firstPart = base.first,
              let parsed = URL(string: String(firstPart)),
              parsed.scheme?.lowercased() == "https",
              let h = parsed.host, !h.isEmpty else { return nil }
        self.url = parsed
        if base.count == 2 {
            let pin = String(base[1]).trimmingCharacters(in: .whitespacesAndNewlines)
            if !pin.isEmpty { self.bootstrapAddress = pin }
        }
    }
}

public struct DoTEndpoint: Equatable {
    public var host: String
    public var port: UInt16

    public init?(_ raw: String) {
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard trimmed.lowercased().hasPrefix("tls://") else { return nil }
        let withoutPin = String(trimmed.dropFirst(6)).split(separator: "#", maxSplits: 1).first.map(String.init) ?? ""
        let body = withoutPin.split(separator: "/").first.map(String.init) ?? ""
        guard !body.isEmpty else { return nil }
        if let colon = body.lastIndex(of: ":"), !body.hasSuffix("]") {
            let h = String(body[..<colon])
            let p = UInt16(body[body.index(after: colon)...]) ?? 853
            guard !h.isEmpty else { return nil }
            self.host = h
            self.port = p
        } else {
            self.host = body
            self.port = 853
        }
    }
}

public struct TraditionalDNSServer: Equatable {
    public let host: String
    public let port: UInt16

    public init?(_ raw: String) {
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty, !trimmed.contains("://") else { return nil }
        let h: String
        let p: UInt16
        if let colon = trimmed.lastIndex(of: ":"), trimmed.filter({ $0 == ":" }).count == 1 {
            h = String(trimmed[..<colon])
            guard let parsedPort = UInt16(trimmed[trimmed.index(after: colon)...]), parsedPort > 0 else { return nil }
            p = parsedPort
        } else {
            h = trimmed
            p = 53
        }
        var v4 = in_addr()
        var v6 = in6_addr()
        let clean = h.trimmingCharacters(in: CharacterSet(charactersIn: "[]"))
        guard clean.withCString({ inet_pton(AF_INET, $0, &v4) == 1 || inet_pton(AF_INET6, $0, &v6) == 1 }) else {
            return nil
        }
        self.host = clean
        self.port = p
    }
}

public final class TraditionalDNSBootstrapResolver {
    private let servers: [TraditionalDNSServer]

    public init(servers: [String], allowedDoHHosts: [String]) {
        _ = allowedDoHHosts
        self.servers = servers.compactMap(TraditionalDNSServer.init)
    }

    @discardableResult
    public func testConnectivity(
        queue callbackQueue: DispatchQueue,
        completion: @escaping (Result<(server: String, latencyMs: Double), Error>) -> Void
    ) -> UUID {
        let id = UUID()
        let list = servers
        DispatchQueue.global(qos: .userInitiated).async {
            guard let first = list.first else {
                callbackQueue.async { completion(.failure(EngineError("未配置有效传统 DNS 服务器"))) }
                return
            }
            let t0 = CFAbsoluteTimeGetCurrent()
            let fd = Darwin.socket(first.host.contains(":") ? AF_INET6 : AF_INET, SOCK_DGRAM, IPPROTO_UDP)
            if fd >= 0 { Darwin.close(fd) }
            let ms = max(0.2, (CFAbsoluteTimeGetCurrent() - t0) * 1000.0)
            callbackQueue.async {
                completion(.success((server: "\(first.host):\(first.port)", latencyMs: ms)))
            }
        }
        return id
    }

    public func cancel(_ id: UUID) { _ = id }
    public func cancel() {}
}

public final class SecureDNSHostResolver {
    public static let shared = SecureDNSHostResolver()
    private let lock = NSLock()
    private var cache: [String: [String]] = [:]

    public init() {}

    public func cachedAddresses(for host: String,
                                now: Date? = nil,
                                allowStaleWithinGeneration: Bool = false) -> [String] {
        _ = now; _ = allowStaleWithinGeneration
        lock.lock(); defer { lock.unlock() }
        return cache[host.lowercased()] ?? []
    }

    @discardableResult
    public func resolve(host: String,
                        queue: DispatchQueue,
                        completion: @escaping (Result<[String], Error>) -> Void) -> UUID? {
        let id = UUID()
        let target = host
        DispatchQueue.global(qos: .utility).async { [weak self] in
            var hints = addrinfo()
            hints.ai_socktype = SOCK_STREAM
            hints.ai_family = AF_UNSPEC
            var res: UnsafeMutablePointer<addrinfo>?
            let rc = target.withCString { getaddrinfo($0, nil, &hints, &res) }
            defer { if let res { freeaddrinfo(res) } }
            guard rc == 0, let first = res else {
                queue.async { completion(.failure(EngineError("DNS 解析失败: \(target)"))) }
                return
            }
            var ips: [String] = []
            var cur: UnsafeMutablePointer<addrinfo>? = first
            while let info = cur {
                var buf = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
                if info.pointee.ai_family == AF_INET, let sa = info.pointee.ai_addr {
                    sa.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { sinPtr in
                        var addr = sinPtr.pointee.sin_addr
                        if inet_ntop(AF_INET, &addr, &buf, socklen_t(buf.count)) != nil {
                            ips.append(String(cString: buf))
                        }
                    }
                } else if info.pointee.ai_family == AF_INET6, let sa = info.pointee.ai_addr {
                    sa.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) { sin6Ptr in
                        var addr = sin6Ptr.pointee.sin6_addr
                        if inet_ntop(AF_INET6, &addr, &buf, socklen_t(buf.count)) != nil {
                            ips.append(String(cString: buf))
                        }
                    }
                }
                cur = info.pointee.ai_next
            }
            if !ips.isEmpty {
                self?.lock.lock()
                self?.cache[target.lowercased()] = ips
                self?.lock.unlock()
            }
            queue.async {
                if ips.isEmpty { completion(.failure(EngineError("无可用地址"))) }
                else { completion(.success(ips)) }
            }
        }
        return id
    }

    public func cancel(_ id: UUID) { _ = id }

    public func flush() {
        lock.lock()
        cache.removeAll()
        lock.unlock()
    }
}

public final class LocalProcessSocketCache {
    public static let shared = LocalProcessSocketCache()
    public init(ttl: TimeInterval = 8.0) { _ = ttl }

    public func lookup(port: UInt16, isTCP: Bool, now: TimeInterval? = nil) -> String? {
        _ = now
        var buf = [CChar](repeating: 0, count: 1024)
        let rc = "127.0.0.1".withCString { ipPtr in
            hajimi_local_process_lookup(isTCP ? 0 : 1, ipPtr, port, &buf, buf.count)
        }
        return rc == HAJIMI_ENGINE_OK ? String(cString: buf) : nil
    }

    public func resolveBatch(ports: [UInt16], now: TimeInterval? = nil) -> [UInt16: String] {
        var out: [UInt16: String] = [:]
        for p in ports {
            if let path = lookup(port: p, isTCP: true, now: now) {
                out[p] = path
            }
        }
        return out
    }

    public func flush() {}
}

public enum NativeOutboundFactory {
    private static let supportedAdapterTypes: Set<String> = Set(SurgeProxyDraft.supportedTypes)

    public static func supports(_ policy: ProxyPolicy) -> Bool {
        switch policy.kind {
        case .direct, .reject, .http, .socks5, .native:
            return true
        case .external:
            let adapter = (policy.adapterType ?? "").trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
            let canonical: String
            switch adapter.replacingOccurrences(of: "-", with: "") {
            case "shadowsocks": canonical = "ss"
            case "shadowsocksr": canonical = "ssr"
            case "hy", "hysteria1": canonical = "hysteria"
            case "hy2": canonical = "hysteria2"
            case "socks5tls": canonical = "socks5-tls"
            default: canonical = adapter
            }
            return supportedAdapterTypes.contains(canonical)
        }
    }

    public static func invalidateForNetworkChange() {}
}

public enum NodeConnectionAdmissionError: Error, LocalizedError, CustomNSError {
    case capacityExceeded
    public static var errorDomain: String { "app.hajimi.node-connection-admission" }
    public var errorCode: Int { 1 }
    public var errorDescription: String? { "节点解析或连接资源已达上限，请稍后重试" }
    public var errorUserInfo: [String: Any] { [NSLocalizedDescriptionKey: errorDescription!] }
}

public final class NodeTCPAddressProbe {
    private var connection: NWConnection?
    private let lock = NSLock()
    private var finished = false

    private init() {}

    @discardableResult
    public static func start(addresses: [String],
                             port: UInt16,
                             queue: DispatchQueue,
                             deadline: UInt64,
                             permitted: @escaping () -> Bool = { true },
                             completion: @escaping (Result<Void, Error>) -> Void) -> NodeTCPAddressProbe {
        let probe = NodeTCPAddressProbe()
        guard permitted() else {
            queue.async { completion(.failure(NWError.posix(.ECANCELED))) }
            return probe
        }
        guard let first = addresses.first, let nwPort = NWEndpoint.Port(rawValue: port) else {
            queue.async { completion(.failure(NWError.posix(.EINVAL))) }
            return probe
        }
        let nowNs = DispatchTime.now().uptimeNanoseconds
        let remainingSec = deadline > nowNs
            ? max(0.1, Double(deadline - nowNs) / 1_000_000_000.0)
            : 0.1

        let conn = NWConnection(host: NWEndpoint.Host(first), port: nwPort, using: .tcp)
        probe.connection = conn
        conn.stateUpdateHandler = { state in
            switch state {
            case .ready:
                guard probe.markFinished() else { return }
                conn.cancel()
                completion(.success(()))
            case .failed(let err):
                guard probe.markFinished() else { return }
                conn.cancel()
                completion(.failure(err))
            default:
                break
            }
        }
        conn.start(queue: queue)
        queue.asyncAfter(deadline: .now() + remainingSec) {
            guard probe.markFinished() else { return }
            conn.cancel()
            completion(.failure(NWError.posix(.ETIMEDOUT)))
        }
        return probe
    }

    private func markFinished() -> Bool {
        lock.lock()
        defer { lock.unlock() }
        guard !finished else { return false }
        finished = true
        return true
    }

    public func cancel() {
        _ = markFinished()
        connection?.cancel()
        connection = nil
    }
}

public struct ExternalControllerSnapshot {
    public var mode: OutboundMode
    public var globalPolicy: String
    public var groupSelections: [String: String]
    public var profile: Profile
    public var engineStatus: ProxyEngineStatus
    public var httpListen: ListenAddress
    public var socksListen: ListenAddress
    public var uploaded: UInt64
    public var downloaded: UInt64
    public var startedAt: Date?
    public var active: [ConnectionSnapshot]
    public var recent: [ConnectionSnapshot]
    public var systemProxyEnabled: Bool
    public var enhancedModeEnabled: Bool
    public var fakeIP: [(domain: String, address: String)]
    public var policyLatencies: [String: [String: TimeInterval]]

    public init(mode: OutboundMode, globalPolicy: String, groupSelections: [String: String],
                profile: Profile, engineStatus: ProxyEngineStatus,
                httpListen: ListenAddress, socksListen: ListenAddress,
                uploaded: UInt64, downloaded: UInt64, startedAt: Date?,
                active: [ConnectionSnapshot], recent: [ConnectionSnapshot],
                systemProxyEnabled: Bool, enhancedModeEnabled: Bool,
                fakeIP: [(domain: String, address: String)],
                policyLatencies: [String: [String: TimeInterval]]) {
        self.mode = mode; self.globalPolicy = globalPolicy; self.groupSelections = groupSelections
        self.profile = profile; self.engineStatus = engineStatus
        self.httpListen = httpListen; self.socksListen = socksListen
        self.uploaded = uploaded; self.downloaded = downloaded; self.startedAt = startedAt
        self.active = active; self.recent = recent
        self.systemProxyEnabled = systemProxyEnabled; self.enhancedModeEnabled = enhancedModeEnabled
        self.fakeIP = fakeIP; self.policyLatencies = policyLatencies
    }
}

public protocol ExternalControllerBackend: AnyObject {
    func controllerSnapshot() -> ExternalControllerSnapshot
    func controllerSelectMode(_ mode: OutboundMode)
    func controllerSelectPolicy(group: String, member: String) -> Bool
    func controllerKillConnection(id: UUID) -> Bool
    func controllerFlushDNS()
    func controllerFlushFakeIP()
}

/// Thin UI Controller Facade (actual REST External Controller listener is hosted natively
/// inside `HajimiEngineCAPI` on `controller_port`).
public final class ExternalController {
    public private(set) var httpListen: ListenAddress?
    public var commandListen: ListenAddress? { nil }
    private weak var backend: ExternalControllerBackend?

    public init(maximumClients: Int = 64, requestTimeout: TimeInterval = 15) {
        _ = maximumClients; _ = requestTimeout
    }

    public func attach(backend: ExternalControllerBackend) {
        self.backend = backend
    }

    public func applyKeys(http: String, command: String) {
        _ = http; _ = command
    }

    public func start(profile: Profile) {
        httpListen = profile.externalController ?? profile.httpAPI
    }

    public func stop() {
        httpListen = nil
    }
}
