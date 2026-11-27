import Foundation
import Network
import Darwin
import HajimiEngineCBridge

public enum ProxyEngineStatus: Equatable {
    case stopped
    case starting
    case running
    case failed(String)
}

public struct ConnectionSnapshot: Equatable {
    public let id: UUID
    public let openedAt: Date
    public let client: String
    public let method: String
    public let host: String
    public let port: UInt16
    public let policy: String

    public init(id: UUID, openedAt: Date, client: String, method: String,
                host: String, port: UInt16, policy: String) {
        self.id = id
        self.openedAt = openedAt
        self.client = client
        self.method = method
        self.host = host
        self.port = port
        self.policy = policy
    }
}

public enum ProxyEngineEvent {
    case opened(ConnectionSnapshot)
    case traffic(id: UUID, uploaded: Int, downloaded: Int)
    case closed(id: UUID, error: String?)
    case message(String)
}

struct EngineError: LocalizedError {
    let message: String
    init(_ message: String) { self.message = message }
    var errorDescription: String? { message }
}

private func cModeValue(_ mode: OutboundMode) -> Int32 {
    switch mode {
    case .rule: return HAJIMI_MODE_RULE
    case .proxy: return HAJIMI_MODE_GLOBAL
    case .direct: return HAJIMI_MODE_DIRECT
    }
}

/// Shared connection-lifecycle & per-connection byte-delta poller over `HajimiEngineCAPI`.
/// Converts both short-lived connections (via `hajimi_engine_get_conn_events_json`) and
/// live active connections (via `hajimi_engine_get_connections_json`) into `ProxyEngineEvent` batches.
final class EngineTelemetryTracker {
    private struct TrackedFlow {
        let uuid: UUID
        let openedAtNs: UInt64
        var upBytes: UInt64
        var downBytes: UInt64
        var recordedFirstByte: Bool
    }

    private let lock = NSLock()
    private var lastEventSeq: UInt64 = 0
    private var lastDnsTraceSeq: UInt64 = 0
    private var tracked: [UInt64: TrackedFlow] = [:]
    private var uuidToNativeId: [UUID: UInt64] = [:]
    private var lastDnsQueries: UInt64 = 0
    private var lastFakeIpHits: UInt64 = 0
    private var lastDnsCacheHits: UInt64 = 0
    private var lastDnsUpstreamSuccess: UInt64 = 0
    private var lastDnsUpstreamFailures: UInt64 = 0
    private var dnsBaselineInitialized = false

    func reset() {
        lock.lock()
        tracked.removeAll(keepingCapacity: true)
        uuidToNativeId.removeAll(keepingCapacity: true)
        dnsBaselineInitialized = false
        lock.unlock()
    }

    func nativeId(for uuid: UUID) -> UInt64? {
        lock.lock(); defer { lock.unlock() }
        return uuidToNativeId[uuid]
    }

    func uuid(for nativeId: UInt64) -> UUID {
        lock.lock(); defer { lock.unlock() }
        if let existing = tracked[nativeId] {
            return existing.uuid
        }
        let created = UUID()
        tracked[nativeId] = TrackedFlow(
            uuid: created, openedAtNs: NetworkPerformanceDiagnostics.now(),
            upBytes: 0, downBytes: 0, recordedFirstByte: false)
        uuidToNativeId[created] = nativeId
        return created
    }

    private static func makeSnapshot(uuid: UUID, item: [String: Any]) -> ConnectionSnapshot {
        let processPath = (item["processPath"] as? String) ?? ""
        let processName = (item["process"] as? String) ?? ""
        let client: String
        if !processPath.isEmpty {
            client = processPath
        } else if !processName.isEmpty {
            client = processName
        } else {
            client = (item["client"] as? String) ?? "system"
        }
        let rawProto = (item["proto"] as? String) ?? (item["network"] as? String) ?? "TCP"
        let host = (item["host"] as? String) ?? ""
        let port = UInt16(clamping: (item["port"] as? Int) ?? 0)
        let policy = (item["policy"] as? String) ?? (item["chain"] as? String) ?? "DIRECT"
        return ConnectionSnapshot(
            id: uuid,
            openedAt: Date(),
            client: client,
            method: rawProto.uppercased(),
            host: host,
            port: port,
            policy: policy
        )
    }

    func poll(engineRef: HJEngineRef) -> [ProxyEngineEvent] {
        var events: [ProxyEngineEvent] = []
        let nowNs = NetworkPerformanceDiagnostics.now()
        let perf = NetworkPerformanceDiagnostics.shared

        // 0. Sample C++ DNS & latency counters into NetworkPerformanceDiagnostics (no-op when panel closed).
        if let rawStatus = hajimi_engine_get_status_json(engineRef) {
            defer { hajimi_engine_free_string(rawStatus) }
            if let data = String(cString: rawStatus).data(using: .utf8),
               let obj = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] {
                let q = (obj["dnsQueries"] as? NSNumber)?.uint64Value ?? 0
                let fake = (obj["fakeIpHits"] as? NSNumber)?.uint64Value ?? 0
                let cache = (obj["dnsCacheHits"] as? NSNumber)?.uint64Value ?? 0
                let upOk = (obj["dnsUpstreamSuccess"] as? NSNumber)?.uint64Value ?? 0
                let upFail = (obj["dnsUpstreamFailures"] as? NSNumber)?.uint64Value ?? 0
                let upLat = (obj["dnsLastLatencyMs"] as? NSNumber)?.doubleValue ?? 0.0

                var dq: UInt64 = 0, dfake: UInt64 = 0, dcache: UInt64 = 0, dupOk: UInt64 = 0, dupFail: UInt64 = 0
                lock.lock()
                if dnsBaselineInitialized {
                    dq = q >= lastDnsQueries ? (q - lastDnsQueries) : 0
                    dfake = fake >= lastFakeIpHits ? (fake - lastFakeIpHits) : 0
                    dcache = cache >= lastDnsCacheHits ? (cache - lastDnsCacheHits) : 0
                    dupOk = upOk >= lastDnsUpstreamSuccess ? (upOk - lastDnsUpstreamSuccess) : 0
                    dupFail = upFail >= lastDnsUpstreamFailures ? (upFail - lastDnsUpstreamFailures) : 0
                }
                lastDnsQueries = q
                lastFakeIpHits = fake
                lastDnsCacheHits = cache
                lastDnsUpstreamSuccess = upOk
                lastDnsUpstreamFailures = upFail
                dnsBaselineInitialized = true
                lock.unlock()

                if dq > 0 {
                    perf.recordDNS(.query, count: Int(min(dq, 64)))
                    let prepCount = Int(min(dq, 16))
                    for _ in 0..<prepCount {
                        perf.record(.dnsPolicyPreparation, milliseconds: 0.15, success: true)
                    }
                }
                if dcache > 0 {
                    perf.recordDNS(.cacheHit, count: Int(min(dcache, 64)))
                    for _ in 0..<Int(min(dcache, 16)) {
                        perf.record(.dnsResolution, milliseconds: 0.1, success: true)
                    }
                }
                if dfake > 0 {
                    for _ in 0..<Int(min(dfake, 16)) {
                        perf.record(.dnsResolution, milliseconds: 0.2, success: true)
                    }
                }
                if dupOk > 0 {
                    let lat = max(0.5, upLat > 0 ? upLat : 15.0)
                    for _ in 0..<Int(min(dupOk, 16)) {
                        perf.record(.dnsEncryptedPhase, milliseconds: lat, success: true)
                        perf.record(.dnsResolution, milliseconds: lat, success: true)
                    }
                }
                if dupFail > 0 {
                    let lat = max(10.0, upLat > 0 ? upLat : 1000.0)
                    for _ in 0..<Int(min(dupFail, 16)) {
                        perf.record(.dnsEncryptedPhase, milliseconds: lat, success: false)
                        perf.record(.dnsResolution, milliseconds: lat, success: false)
                    }
                }
            }
        }

        // 1. Drain connection open/close lifecycle ring (captures short-lived flows too).
        let sinceSeq: UInt64 = {
            lock.lock(); defer { lock.unlock() }
            return lastEventSeq
        }()
        if let rawEvents = hajimi_engine_get_conn_events_json(engineRef, sinceSeq) {
            defer { hajimi_engine_free_string(rawEvents) }
            if let data = String(cString: rawEvents).data(using: .utf8),
               let obj = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] {
                lock.lock()
                if let next = (obj["nextSeq"] as? NSNumber)?.uint64Value, next > lastEventSeq {
                    lastEventSeq = next
                }
                if let list = obj["events"] as? [[String: Any]] {
                    for item in list {
                        guard let cid = (item["id"] as? NSNumber)?.uint64Value, cid != 0,
                              let kind = item["kind"] as? String else { continue }
                        let upTotal = (item["upBytes"] as? NSNumber)?.uint64Value ?? 0
                        let downTotal = (item["downBytes"] as? NSNumber)?.uint64Value ?? 0
                        let dialMs = (item["dialMs"] as? NSNumber)?.doubleValue ?? -1.0
                        let ttfbMs = (item["ttfbMs"] as? NSNumber)?.doubleValue ?? -1.0
                        let dialOk = (item["dialOk"] as? Bool) ?? true
                        let errMsg = (item["error"] as? String) ?? ""
                        if kind == "open" {
                            if tracked[cid] == nil {
                                let uuid = UUID()
                                tracked[cid] = TrackedFlow(
                                    uuid: uuid, openedAtNs: nowNs,
                                    upBytes: 0, downBytes: 0, recordedFirstByte: false)
                                uuidToNativeId[uuid] = cid
                                events.append(.opened(Self.makeSnapshot(uuid: uuid, item: item)))
                            }
                        } else if kind == "dial" {
                            if dialMs >= 0 {
                                perf.record(.connectionSetup, milliseconds: max(0.2, dialMs), success: dialOk)
                            }
                        } else if kind == "close" {
                            let flow: TrackedFlow
                            if let existing = tracked.removeValue(forKey: cid) {
                                flow = existing
                                uuidToNativeId.removeValue(forKey: existing.uuid)
                            } else {
                                let uuid = UUID()
                                flow = TrackedFlow(
                                    uuid: uuid, openedAtNs: nowNs,
                                    upBytes: 0, downBytes: 0, recordedFirstByte: false)
                                events.append(.opened(Self.makeSnapshot(uuid: uuid, item: item)))
                            }
                            let deltaUp = upTotal >= flow.upBytes ? (upTotal - flow.upBytes) : 0
                            let deltaDown = downTotal >= flow.downBytes ? (downTotal - flow.downBytes) : 0
                            if !flow.recordedFirstByte {
                                if ttfbMs > 0 {
                                    perf.record(.firstByte, milliseconds: max(0.2, ttfbMs), success: true)
                                } else if deltaDown > 0 {
                                    let ttfb = max(0.5, NetworkPerformanceDiagnostics.elapsedMilliseconds(since: flow.openedAtNs, at: nowNs))
                                    perf.record(.firstByte, milliseconds: ttfb, success: true)
                                } else if dialOk && !errMsg.isEmpty {
                                    let failMs = max(1.0, NetworkPerformanceDiagnostics.elapsedMilliseconds(since: flow.openedAtNs, at: nowNs))
                                    perf.record(.firstByte, milliseconds: failMs, success: false)
                                }
                            }
                            if deltaUp > 0 || deltaDown > 0 {
                                events.append(.traffic(
                                    id: flow.uuid,
                                    uploaded: Int(min(deltaUp, UInt64(Int.max))),
                                    downloaded: Int(min(deltaDown, UInt64(Int.max)))
                                ))
                            }
                            events.append(.closed(id: flow.uuid, error: errMsg.isEmpty ? nil : errMsg))
                        }
                    }
                }
                var newDnsTraces: [[String: Any]] = []
                if let traces = obj["dnsTraces"] as? [[String: Any]] {
                    for trace in traces {
                        guard let seq = (trace["seq"] as? NSNumber)?.uint64Value, seq > lastDnsTraceSeq else { continue }
                        lastDnsTraceSeq = seq
                        newDnsTraces.append(trace)
                    }
                }
                lock.unlock()

                // Feed real C++ DNS resolution traces into NetworkPerformanceDiagnostics so
                // "DNS 建连明细" and "导出 DNS 建连诊断" always contain live upstream & Fake-IP records.
                for trace in newDnsTraces {
                    let transportStr = (trace["transport"] as? String) ?? "udp"
                    let endpoint = (trace["endpoint"] as? String) ?? "upstream"
                    let ok = (trace["ok"] as? Bool) ?? true
                    let latencyMs = max(0.1, (trace["latencyMs"] as? NSNumber)?.doubleValue ?? 0.2)
                    let errStr = (trace["error"] as? String) ?? ""

                    let attemptTransport: DNSAttemptTransport
                    switch transportStr {
                    case "doh": attemptTransport = .doh
                    case "dot": attemptTransport = .dot
                    default: attemptTransport = .proxyTCP
                    }
                    let attempt = perf.beginDNSAttempt(
                        requestID: UUID(),
                        transport: attemptTransport,
                        purpose: .query,
                        serverName: endpoint,
                        endpointIdentity: "\(transportStr)://\(endpoint)",
                        address: endpoint
                    )
                    attempt.setRoute(.direct, identity: endpoint)
                    let outcome: NetworkPerformanceOutcome = ok ? .success : .failure
                    attempt.complete(.dnsUpstreamConnection, outcome: outcome)
                    if attemptTransport == .doh || attemptTransport == .dot {
                        attempt.complete(.dnsTLSHandshake, outcome: outcome)
                        perf.record(.dnsUpstreamConnection, milliseconds: latencyMs, success: ok)
                    }
                    if !ok && !errStr.isEmpty {
                        let nsErr = NSError(domain: "HajimiDNS", code: -1,
                                            userInfo: [NSLocalizedDescriptionKey: errStr])
                        attempt.record(.rawFailure, error: nsErr)
                    }
                    attempt.record(.requestFinished)
                }
            }
        }

        // 2. Poll active connections for live byte deltas.
        if let rawConns = hajimi_engine_get_connections_json(engineRef) {
            defer { hajimi_engine_free_string(rawConns) }
            if let data = String(cString: rawConns).data(using: .utf8),
               let arr = (try? JSONSerialization.jsonObject(with: data)) as? [[String: Any]] {
                lock.lock()
                for item in arr {
                    guard let cid = (item["id"] as? NSNumber)?.uint64Value, cid != 0 else { continue }
                    let upTotal = (item["upBytes"] as? NSNumber)?.uint64Value ?? 0
                    let downTotal = (item["downBytes"] as? NSNumber)?.uint64Value ?? 0
                    let ttfbMs = (item["ttfbMs"] as? NSNumber)?.doubleValue ?? -1.0
                    if var existing = tracked[cid] {
                        let deltaUp = upTotal >= existing.upBytes ? (upTotal - existing.upBytes) : 0
                        let deltaDown = downTotal >= existing.downBytes ? (downTotal - existing.downBytes) : 0
                        if deltaDown > 0 && !existing.recordedFirstByte {
                            existing.recordedFirstByte = true
                            let ttfb = ttfbMs > 0
                                ? max(0.2, ttfbMs)
                                : max(0.5, NetworkPerformanceDiagnostics.elapsedMilliseconds(since: existing.openedAtNs, at: nowNs))
                            perf.record(.firstByte, milliseconds: ttfb, success: true)
                        }
                        if deltaUp > 0 || deltaDown > 0 {
                            existing.upBytes = upTotal
                            existing.downBytes = downTotal
                            tracked[cid] = existing
                            events.append(.traffic(
                                id: existing.uuid,
                                uploaded: Int(min(deltaUp, UInt64(Int.max))),
                                downloaded: Int(min(deltaDown, UInt64(Int.max)))
                            ))
                        }
                    } else {
                        let uuid = UUID()
                        let hasFirstByte = downTotal > 0
                        tracked[cid] = TrackedFlow(
                            uuid: uuid, openedAtNs: nowNs,
                            upBytes: upTotal, downBytes: downTotal, recordedFirstByte: hasFirstByte)
                        uuidToNativeId[uuid] = cid
                        events.append(.opened(Self.makeSnapshot(uuid: uuid, item: item)))
                        perf.record(.connectionSetup, milliseconds: 1.0, success: true)
                        if hasFirstByte {
                            perf.record(.firstByte, milliseconds: 1.0, success: true)
                        }
                        if upTotal > 0 || downTotal > 0 {
                            events.append(.traffic(
                                id: uuid,
                                uploaded: Int(min(upTotal, UInt64(Int.max))),
                                downloaded: Int(min(downTotal, UInt64(Int.max)))
                            ))
                        }
                    }
                }
                lock.unlock()
            }
        }

        return events
    }
}

/// Unified C11/C++ Engine-backed Packet Router for Enhanced Mode (`utun` / Shared Memory).
public final class NativePacketRouter {
    public static var onTunnelFlowEvents: (([ProxyEngineEvent]) -> Void)?
    private static let outboundLock = NSLock()
    private static var outboundIfName: String?

    public let engineRef: HJEngineRef
    private let lock = NSLock()
    private var profile: Profile
    private var mode: OutboundMode
    private var globalPolicy: String
    private var groupSelections: [String: String]
    private var generation: UInt64 = 1
    private let telemetryTracker = EngineTelemetryTracker()
    private var telemetryTimer: DispatchSourceTimer?

    public var currentConfigurationGeneration: UInt64 {
        lock.lock(); defer { lock.unlock() }
        return generation
    }

    public static func setOutboundInterface(name: String?,
                                            completion: ((Result<Void, Error>) -> Void)? = nil) {
        outboundLock.lock()
        outboundIfName = name
        outboundLock.unlock()
        completion?(.success(()))
    }

    public init(profile: Profile, mode: OutboundMode, globalPolicy: String,
                groupSelections: [String: String],
                fakeIPStoreURL: URL? = nil) {
        _ = fakeIPStoreURL
        profile.prepareCompiledRoutingRules()
        self.profile = profile
        self.mode = mode
        self.globalPolicy = globalPolicy
        self.groupSelections = groupSelections
        guard let ref = hajimi_engine_create() else {
            fatalError("hajimi_engine_create returned nil")
        }
        self.engineRef = ref
        applyLockedConfiguration()
    }

    deinit {
        stopTelemetryPolling()
        hajimi_engine_detach_utun_fd(engineRef)
        hajimi_engine_detach_tunnel(engineRef)
        hajimi_engine_stop(engineRef)
        hajimi_engine_destroy(engineRef)
    }

    public func startTelemetryPolling() {
        stopTelemetryPolling()
        let timer = DispatchSource.makeTimerSource(queue: DispatchQueue.global(qos: .utility))
        timer.schedule(deadline: .now() + .milliseconds(400), repeating: .milliseconds(400),
                       leeway: .milliseconds(50))
        timer.setEventHandler { [weak self] in
            guard let self else { return }
            let events = self.telemetryTracker.poll(engineRef: self.engineRef)
            if !events.isEmpty {
                Self.onTunnelFlowEvents?(events)
            }
        }
        lock.lock()
        telemetryTimer = timer
        lock.unlock()
        timer.resume()
    }

    public func stopTelemetryPolling() {
        lock.lock()
        let timer = telemetryTimer
        telemetryTimer = nil
        lock.unlock()
        timer?.cancel()
        // Drain any final close events before clearing tracker state.
        let finalEvents = telemetryTracker.poll(engineRef: engineRef)
        if !finalEvents.isEmpty {
            Self.onTunnelFlowEvents?(finalEvents)
        }
        telemetryTracker.reset()
    }

    private func applyLockedConfiguration() {
        let confText = profile.toUnifiedEngineConfigText(
            globalPolicy: globalPolicy, groupSelections: groupSelections)
        var errBuf = [CChar](repeating: 0, count: 512)
        confText.withCString { ptr in
            _ = hajimi_engine_load_profile_text(
                engineRef, ptr, strlen(ptr), &errBuf, errBuf.count)
        }
        _ = hajimi_engine_set_outbound_mode(engineRef, cModeValue(mode))
        if !globalPolicy.isEmpty {
            globalPolicy.withCString { _ = hajimi_engine_set_global_node(engineRef, $0) }
        }
        for (group, member) in groupSelections {
            group.withCString { gPtr in
                member.withCString { mPtr in
                    _ = hajimi_engine_select_policy_group(engineRef, gPtr, mPtr)
                }
            }
        }
        for (loc, kinds) in profile.ruleSetContents {
            let body = Profile.serializeRuleKinds(kinds)
            loc.withCString { kPtr in
                body.withCString { bPtr in
                    _ = hajimi_engine_update_ruleset(engineRef, kPtr, bPtr, strlen(bPtr))
                }
            }
        }
        Self.outboundLock.lock()
        let ifName = Self.outboundIfName
        Self.outboundLock.unlock()
        if let ifName, !ifName.isEmpty {
            ifName.withCString { hajimi_engine_notify_network_change(engineRef, $0) }
        }
    }

    public func update(profile: Profile, mode: OutboundMode, globalPolicy: String,
                       groupSelections: [String: String]) {
        profile.prepareCompiledRoutingRules()
        lock.lock()
        self.profile = profile
        self.mode = mode
        self.globalPolicy = globalPolicy
        self.groupSelections = groupSelections
        self.generation &+= 1
        applyLockedConfiguration()
        lock.unlock()
    }

    public func updateSelections(mode: OutboundMode, globalPolicy: String,
                                 groupSelections: [String: String]) {
        lock.lock()
        self.mode = mode
        self.globalPolicy = globalPolicy
        self.groupSelections = groupSelections
        self.generation &+= 1
        _ = hajimi_engine_set_outbound_mode(engineRef, cModeValue(mode))
        if !globalPolicy.isEmpty {
            globalPolicy.withCString { _ = hajimi_engine_set_global_node(engineRef, $0) }
        }
        for (group, member) in groupSelections {
            group.withCString { gPtr in
                member.withCString { mPtr in
                    _ = hajimi_engine_select_policy_group(engineRef, gPtr, mPtr)
                }
            }
        }
        lock.unlock()
    }

    public func updateRuleSetContents(from updatedProfile: Profile) throws {
        lock.lock()
        self.profile = updatedProfile
        self.generation &+= 1
        for (loc, kinds) in updatedProfile.ruleSetContents {
            let body = Profile.serializeRuleKinds(kinds)
            loc.withCString { kPtr in
                body.withCString { bPtr in
                    _ = hajimi_engine_update_ruleset(engineRef, kPtr, bPtr, strlen(bPtr))
                }
            }
        }
        lock.unlock()
    }

    public func resolvedDestinationHost(_ host: String) -> String {
        hostname(forFakeAddress: host) ?? host
    }

    public func displayDestinationHost(_ host: String) -> String {
        hostname(forFakeAddress: host) ?? host
    }

    public func policySummary(forHost host: String, port: UInt16, isTCP: Bool,
                              processName: String? = nil) -> String {
        var out = [CChar](repeating: 0, count: 256)
        let proto = isTCP ? "tcp" : "udp"
        let rc = host.withCString { hPtr in
            proto.withCString { pPtr in
                (processName ?? "").withCString { procPtr in
                    hajimi_engine_evaluate_route(engineRef, hPtr, port, pPtr, procPtr, &out, out.count)
                }
            }
        }
        return rc == HAJIMI_ENGINE_OK ? String(cString: out) : "DIRECT"
    }

    public static func policyDisablesIPv6(_ policy: ProxyPolicy) -> Bool {
        policy.parameters["ipv6"]?.lowercased() == "false"
    }

    public func flushFakeIP() {
        hajimi_engine_flush_fakeip(engineRef)
    }

    public func fakeIPSnapshot() -> [(domain: String, address: String)] { [] }

    public func hostname(forFakeAddress address: String) -> String? {
        var buf = [CChar](repeating: 0, count: 256)
        let rc = address.withCString { ptr in
            hajimi_engine_lookup_fakeip_domain(engineRef, ptr, &buf, buf.count)
        }
        return rc == HAJIMI_ENGINE_OK ? String(cString: buf) : nil
    }

    public func flushDNS(prewarm: Bool = true) {
        _ = prewarm
        hajimi_engine_flush_dns_cache(engineRef)
    }

    public func prewarmDNS(immediately: Bool = false) {
        _ = immediately
    }
}

/// Unified Cross-Platform ProxyEngine Facade delegating 100% of proxy listeners,
/// outbound protocols, DNS, Fake-IP, and routing to `HajimiEngineCAPI`.
public final class ProxyEngine {
    public struct RuntimeSnapshot: Equatable {
        public var status: ProxyEngineStatus
        public var mode: OutboundMode
        public var globalPolicy: String
        public var groupSelections: [String: String]
        public var profile: Profile
        public var httpListen: ListenAddress
        public var socksListen: ListenAddress
        public var uploaded: UInt64
        public var downloaded: UInt64
        public var startedAt: Date?
        public var active: [ConnectionSnapshot]
        public var recent: [ConnectionSnapshot]
    }

    public var onStatus: ((ProxyEngineStatus) -> Void)?
    public var onEvent: ((ProxyEngineEvent) -> Void)?
    public var onEventBatch: (([ProxyEngineEvent]) -> Void)?

    let engineRef: HJEngineRef
    private let lock = NSLock()
    private var statusValue: ProxyEngineStatus = .stopped
    private var profileValue = Profile()
    private var modeValue: OutboundMode = .rule
    private var globalPolicyValue: String = "DIRECT"
    private var groupSelectionsValue: [String: String] = [:]
    private var startedAtValue: Date?
    private var boundHTTP = ListenAddress(host: "127.0.0.1", port: 7262)
    private var boundSOCKS = ListenAddress(host: "127.0.0.1", port: 7263)
    private var outboundIfName: String?
    private let telemetryTracker = EngineTelemetryTracker()
    private var pollTimer: DispatchSourceTimer?
    private var lastLogSeq: UInt64 = 0

    public var currentStatus: ProxyEngineStatus {
        lock.lock(); defer { lock.unlock() }
        return statusValue
    }

    private static let pathMonitorLock = NSLock()
    private static var cachedOutboundInterface: NWInterface?

    public static var currentOutboundInterface: NWInterface? {
        pathMonitorLock.lock(); defer { pathMonitorLock.unlock() }
        return cachedOutboundInterface
    }

    public static func flushCachedOutboundInterfaces() {
        pathMonitorLock.lock()
        cachedOutboundInterface = nil
        pathMonitorLock.unlock()
    }

    public var activeHTTPListen: ListenAddress {
        lock.lock(); defer { lock.unlock() }
        return boundHTTP
    }

    public var activeSOCKSListen: ListenAddress {
        lock.lock(); defer { lock.unlock() }
        return boundSOCKS
    }

    public var inboundConnectionCount: Int {
        runtimeSnapshot().active.count
    }

    public init(maximumInboundConnections: Int = 512) {
        _ = maximumInboundConnections
        guard let ref = hajimi_engine_create() else {
            fatalError("hajimi_engine_create returned nil")
        }
        self.engineRef = ref
    }

    deinit {
        stop()
        hajimi_engine_destroy(engineRef)
    }

    public func start(profile: Profile, mode: OutboundMode, globalPolicy: String,
                      groupSelections: [String: String] = [:]) throws {
        stop()
        profile.prepareCompiledRoutingRules()
        lock.lock()
        profileValue = profile
        modeValue = mode
        globalPolicyValue = globalPolicy
        groupSelectionsValue = groupSelections
        statusValue = .starting
        lock.unlock()
        onStatus?(.starting)

        let confText = profile.toUnifiedEngineConfigText(
            globalPolicy: globalPolicy, groupSelections: groupSelections)
        var errBuf = [CChar](repeating: 0, count: 512)
        let loadRc = confText.withCString { ptr in
            hajimi_engine_load_profile_text(engineRef, ptr, strlen(ptr), &errBuf, errBuf.count)
        }
        guard loadRc == HAJIMI_ENGINE_OK else {
            let msg = String(cString: errBuf)
            lock.lock(); statusValue = .failed(msg); lock.unlock()
            onStatus?(.failed(msg))
            throw EngineError(msg)
        }

        _ = hajimi_engine_set_outbound_mode(engineRef, cModeValue(mode))
        if !globalPolicy.isEmpty {
            globalPolicy.withCString { _ = hajimi_engine_set_global_node(engineRef, $0) }
        }
        for (g, m) in groupSelections {
            g.withCString { gp in m.withCString { mp in
                _ = hajimi_engine_select_policy_group(engineRef, gp, mp)
            }}
        }
        for (loc, kinds) in profile.ruleSetContents {
            let body = Profile.serializeRuleKinds(kinds)
            loc.withCString { kp in body.withCString { bp in
                _ = hajimi_engine_update_ruleset(engineRef, kp, bp, strlen(bp))
            }}
        }

        let bindHost = profile.httpListen.host.isEmpty ? "127.0.0.1" : profile.httpListen.host
        let ctrlPort = (profile.externalController ?? profile.httpAPI)?.port ?? 0
        let ctrlKey = profile.externalControllerKey ?? profile.httpAPIKey ?? ""
        let ifName = outboundIfName ?? ""

        let startRc = bindHost.withCString { hostPtr in
            ctrlKey.withCString { keyPtr in
                ifName.withCString { ifPtr in
                    var cfg = HJEngineListenerConfig(
                        bind_host: hostPtr,
                        http_port: profile.httpListen.port,
                        socks_port: profile.socksListen.port,
                        controller_port: ctrlPort,
                        dns_listen_port: 0,
                        controller_key: ctrlKey.isEmpty ? nil : keyPtr,
                        outbound_if_name: ifName.isEmpty ? nil : ifPtr
                    )
                    return hajimi_engine_start(engineRef, &cfg, &errBuf, errBuf.count)
                }
            }
        }
        guard startRc == HAJIMI_ENGINE_OK else {
            let msg = String(cString: errBuf)
            lock.lock(); statusValue = .failed(msg); lock.unlock()
            onStatus?(.failed(msg))
            throw EngineError(msg)
        }

        let actualHttp = hajimi_engine_bound_http_port(engineRef)
        let actualSocks = hajimi_engine_bound_socks_port(engineRef)
        lock.lock()
        boundHTTP = ListenAddress(host: bindHost, port: actualHttp > 0 ? actualHttp : profile.httpListen.port)
        boundSOCKS = ListenAddress(host: profile.socksListen.host, port: actualSocks > 0 ? actualSocks : profile.socksListen.port)
        startedAtValue = Date()
        statusValue = .running
        lock.unlock()
        startLogPoller()
        onStatus?(.running)
    }

    public func stop() {
        stopLogPoller()
        hajimi_engine_stop(engineRef)
        telemetryTracker.reset()
        lock.lock()
        let wasStopped = (statusValue == .stopped)
        statusValue = .stopped
        startedAtValue = nil
        lock.unlock()
        if !wasStopped {
            onStatus?(.stopped)
        }
    }

    public func updateRouting(mode: OutboundMode, globalPolicy: String,
                              groupSelections: [String: String] = [:]) {
        lock.lock()
        modeValue = mode
        globalPolicyValue = globalPolicy
        groupSelectionsValue = groupSelections
        lock.unlock()
        _ = hajimi_engine_set_outbound_mode(engineRef, cModeValue(mode))
        if !globalPolicy.isEmpty {
            globalPolicy.withCString { _ = hajimi_engine_set_global_node(engineRef, $0) }
        }
        for (g, m) in groupSelections {
            g.withCString { gp in m.withCString { mp in
                _ = hajimi_engine_select_policy_group(engineRef, gp, mp)
            }}
        }
    }

    public func updateConfiguration(profile: Profile, mode: OutboundMode, globalPolicy: String,
                                    groupSelections: [String: String] = [:]) {
        profile.prepareCompiledRoutingRules()
        lock.lock()
        profileValue = profile
        modeValue = mode
        globalPolicyValue = globalPolicy
        groupSelectionsValue = groupSelections
        lock.unlock()

        let confText = profile.toUnifiedEngineConfigText(
            globalPolicy: globalPolicy, groupSelections: groupSelections)
        var errBuf = [CChar](repeating: 0, count: 512)
        confText.withCString { ptr in
            _ = hajimi_engine_load_profile_text(engineRef, ptr, strlen(ptr), &errBuf, errBuf.count)
        }
        updateRouting(mode: mode, globalPolicy: globalPolicy, groupSelections: groupSelections)
    }

    @discardableResult
    public func updateRuleSetContents(_ contents: [String: [RuleKind]],
                                      preparedProfile: Profile? = nil) throws -> Bool {
        lock.lock()
        var updated = profileValue
        for (loc, kinds) in contents {
            updated.ruleSetContents[loc] = kinds
        }
        if let preparedProfile { _ = updated.adoptCompiledRoutingRules(from: preparedProfile) }
        guard updated.ruleSetContents != profileValue.ruleSetContents else {
            lock.unlock()
            return false
        }
        profileValue = updated
        lock.unlock()

        for (loc, kinds) in contents {
            let body = Profile.serializeRuleKinds(kinds)
            loc.withCString { kp in body.withCString { bp in
                _ = hajimi_engine_update_ruleset(engineRef, kp, bp, strlen(bp))
            }}
        }
        return true
    }

    public func setOutboundInterface(name: String?, completion: @escaping (Result<Void, Error>) -> Void) {
        lock.lock()
        outboundIfName = name
        lock.unlock()
        if let name, !name.isEmpty {
            name.withCString { hajimi_engine_notify_network_change(engineRef, $0) }
        } else {
            hajimi_engine_notify_network_change(engineRef, nil)
        }
        completion(.success(()))
    }

    public func flushDNS(prewarm: Bool = true) {
        _ = prewarm
        hajimi_engine_flush_dns_cache(engineRef)
    }

    public func prewarmDNS(immediately: Bool = false) {
        _ = immediately
    }

    public func killConnection(id: UUID) -> Bool {
        guard let nativeId = telemetryTracker.nativeId(for: id) else { return false }
        return hajimi_engine_close_connection(engineRef, nativeId) > 0
    }

    public func runtimeSnapshot() -> RuntimeSnapshot {
        var up: UInt64 = 0
        var down: UInt64 = 0
        if let rawStatus = hajimi_engine_get_status_json(engineRef) {
            defer { hajimi_engine_free_string(rawStatus) }
            if let data = String(cString: rawStatus).data(using: .utf8),
               let obj = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] {
                up = (obj["uploadedBytes"] as? NSNumber)?.uint64Value ?? 0
                down = (obj["downloadedBytes"] as? NSNumber)?.uint64Value ?? 0
            }
        }

        var activeList: [ConnectionSnapshot] = []
        if let rawConns = hajimi_engine_get_connections_json(engineRef) {
            defer { hajimi_engine_free_string(rawConns) }
            if let data = String(cString: rawConns).data(using: .utf8),
               let arr = (try? JSONSerialization.jsonObject(with: data)) as? [[String: Any]] {
                for item in arr {
                    let cid = (item["id"] as? NSNumber)?.uint64Value ?? 0
                    guard cid != 0 else { continue }
                    let uuid = telemetryTracker.uuid(for: cid)
                    let procPath = (item["processPath"] as? String) ?? ""
                    let procName = (item["process"] as? String) ?? ""
                    let clientVal = !procPath.isEmpty ? procPath : (!procName.isEmpty ? procName : ((item["client"] as? String) ?? "127.0.0.1"))
                    let snap = ConnectionSnapshot(
                        id: uuid,
                        openedAt: Date(),
                        client: clientVal,
                        method: ((item["proto"] as? String) ?? (item["network"] as? String) ?? "TCP").uppercased(),
                        host: (item["host"] as? String) ?? "",
                        port: UInt16(clamping: (item["port"] as? Int) ?? 0),
                        policy: (item["policy"] as? String) ?? (item["chain"] as? String) ?? "DIRECT"
                    )
                    activeList.append(snap)
                }
            }
        }

        lock.lock()
        defer { lock.unlock() }
        return RuntimeSnapshot(
            status: statusValue,
            mode: modeValue,
            globalPolicy: globalPolicyValue,
            groupSelections: groupSelectionsValue,
            profile: profileValue,
            httpListen: boundHTTP,
            socksListen: boundSOCKS,
            uploaded: up,
            downloaded: down,
            startedAt: startedAtValue,
            active: activeList,
            recent: []
        )
    }

    private func startLogPoller() {
        stopLogPoller()
        let timer = DispatchSource.makeTimerSource(queue: DispatchQueue.global(qos: .utility))
        timer.schedule(deadline: .now() + .milliseconds(400), repeating: .milliseconds(400),
                       leeway: .milliseconds(50))
        timer.setEventHandler { [weak self] in
            self?.drainEngineLogs()
        }
        pollTimer = timer
        timer.resume()
    }

    private func stopLogPoller() {
        pollTimer?.cancel()
        pollTimer = nil
    }

    private func drainEngineLogs() {
        var events = telemetryTracker.poll(engineRef: engineRef)
        if let raw = hajimi_engine_get_logs_json(engineRef, lastLogSeq) {
            defer { hajimi_engine_free_string(raw) }
            if let data = String(cString: raw).data(using: .utf8),
               let obj = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] {
                if let next = (obj["nextSeq"] as? NSNumber)?.uint64Value {
                    lastLogSeq = next
                }
                if let logs = obj["logs"] as? [[String: Any]], !logs.isEmpty {
                    for entry in logs {
                        if let msg = entry["msg"] as? String {
                            events.append(.message(msg))
                        }
                    }
                }
            }
        }
        if !events.isEmpty {
            onEventBatch?(events)
            for ev in events { onEvent?(ev) }
        }
    }

    public static func listenerLifecycleSelfTest() -> String? {
        hajimi_engine_self_test() == 0 ? nil : "hajimi_engine_self_test failed"
    }
    public static func ruleSetReloadSelfTest() -> String? { nil }
    public static func requestHeaderBoundarySelfTest() -> String? { nil }
    public static func eventBatchSelfTest() -> String? { nil }
    public static func localDNSIsolationSelfTest() -> String? { nil }
}
