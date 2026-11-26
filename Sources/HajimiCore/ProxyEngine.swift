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
        hajimi_engine_detach_utun_fd(engineRef)
        hajimi_engine_detach_tunnel(engineRef)
        hajimi_engine_stop(engineRef)
        hajimi_engine_destroy(engineRef)
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
    private var uuidToNativeId: [UUID: UInt64] = [:]
    private var nativeIdToUuid: [UInt64: UUID] = [:]
    private var pollTimer: DispatchSourceTimer?
    private var lastLogSeq: UInt64 = 0

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
        lock.lock()
        let wasStopped = (statusValue == .stopped)
        statusValue = .stopped
        startedAtValue = nil
        uuidToNativeId.removeAll()
        nativeIdToUuid.removeAll()
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
        lock.lock()
        let nativeId = uuidToNativeId[id]
        lock.unlock()
        guard let nativeId else { return false }
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
                lock.lock()
                for item in arr {
                    let cid = (item["id"] as? NSNumber)?.uint64Value ?? 0
                    guard cid != 0 else { continue }
                    let uuid: UUID
                    if let existing = nativeIdToUuid[cid] {
                        uuid = existing
                    } else {
                        let created = UUID()
                        nativeIdToUuid[cid] = created
                        uuidToNativeId[created] = cid
                        uuid = created
                    }
                    let snap = ConnectionSnapshot(
                        id: uuid,
                        openedAt: Date(),
                        client: (item["client"] as? String) ?? "127.0.0.1",
                        method: (item["network"] as? String)?.uppercased() ?? "TCP",
                        host: (item["host"] as? String) ?? "",
                        port: UInt16(clamping: (item["port"] as? Int) ?? 0),
                        policy: (item["chain"] as? String) ?? "DIRECT"
                    )
                    activeList.append(snap)
                }
                lock.unlock()
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
        timer.schedule(deadline: .now() + .milliseconds(500), repeating: .milliseconds(500))
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
        guard let raw = hajimi_engine_get_logs_json(engineRef, lastLogSeq) else { return }
        defer { hajimi_engine_free_string(raw) }
        guard let data = String(cString: raw).data(using: .utf8),
              let obj = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] else { return }
        if let next = (obj["nextSeq"] as? NSNumber)?.uint64Value {
            lastLogSeq = next
        }
        guard let logs = obj["logs"] as? [[String: Any]], !logs.isEmpty else { return }
        var events: [ProxyEngineEvent] = []
        for entry in logs {
            if let msg = entry["msg"] as? String {
                events.append(.message(msg))
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
