import Foundation
import Darwin

/// Value-only rule interpreter used by UI inspection, PolicyHealthMonitor, and semantic verification.
public enum RoutingRuleMatcher {
    public static func matches(_ kind: RuleKind, target: RequestTarget) -> Bool {
        matches(kind, target: target, domainMatcher: nil)
    }

    package static func matches(_ kind: RuleKind, target: RequestTarget,
                                domainMatcher: RoutingDomainMatcher?) -> Bool {
        var cachedNormalizedHost: String?
        func normalizedHost() -> String {
            if let existing = cachedNormalizedHost { return existing }
            let computed = DomainPattern.trimDotsAndLowercase(target.host)
            cachedNormalizedHost = computed
            return computed
        }
        switch kind {
        case .domain(let value):
            if let match = domainMatcher?(target.host, value, .exact) { return match }
            return normalizedHost() == value.lowercased()
        case .domainSuffix(let value):
            if let match = domainMatcher?(target.host, value, .suffix) { return match }
            let host = normalizedHost()
            let suffix = DomainPattern.trimDotsAndLowercase(value)
            return host == suffix || host.hasSuffix("." + suffix)
        case .domainKeyword(let value):
            if let match = domainMatcher?(target.host, value, .keyword) { return match }
            return normalizedHost().contains(value.lowercased())
        case .domainWildcard(let value):
            return DomainPattern.wildcard(value, matches: normalizedHost())
        case .ipCIDR(let cidr):
            return IPCIDR.contains(normalizedHost(), cidr: cidr)
        case .destinationPort(let range):
            return range.contains(target.port)
        case .sourceIPCIDR(let cidr):
            guard let source = target.sourceHost else { return false }
            return IPCIDR.contains(source, cidr: cidr)
        case .sourcePort(let range):
            guard let port = target.sourcePort else { return false }
            return range.contains(port)
        case .inboundPort(let range):
            guard let port = target.inboundPort else { return false }
            return range.contains(port)
        case .protocolName(let value):
            return target.protocolName.caseInsensitiveCompare(value) == .orderedSame
        case .processName(let expected):
            guard let actual = target.processName?.trimmingCharacters(in: .whitespacesAndNewlines),
                  !actual.isEmpty else { return false }
            let needle = expected.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !needle.isEmpty else { return false }
            if actual.caseInsensitiveCompare(needle) == .orderedSame { return true }
            let actualBase = (actual as NSString).lastPathComponent
            let needleBase = (needle as NSString).lastPathComponent
            if !actualBase.isEmpty && actualBase.caseInsensitiveCompare(needleBase) == .orderedSame {
                return true
            }
            for component in actual.split(separator: "/") where component.lowercased().hasSuffix(".app") {
                if component.caseInsensitiveCompare(needleBase) == .orderedSame {
                    return true
                }
            }
            return false
        case .geoIP, .ipASN:
            return false
        case .logicalAnd(let children):
            return !children.isEmpty && children.allSatisfy {
                matches($0, target: target, domainMatcher: domainMatcher)
            }
        case .logicalOr(let children):
            return children.contains { matches($0, target: target, domainMatcher: domainMatcher) }
        case .logicalNot(let child):
            return !matches(child, target: target, domainMatcher: domainMatcher)
        case .ruleSet:
            return false
        case .final:
            return true
        }
    }

    package static func matches(_ rule: RoutingRule, target: RequestTarget,
                                alternateHost: String?, ruleSetContents: [String: [RuleKind]],
                                domainMatcher: RoutingDomainMatcher?) -> Bool {
        if case .ruleSet(let reference) = rule.kind {
            guard let contents = ruleSetContents[reference.location] else { return false }
            return contents.contains { kind in
                guard let candidate = matchTarget(for: kind, target: target,
                                                  alternateHost: alternateHost) else { return false }
                return matches(kind, target: candidate, domainMatcher: domainMatcher)
            }
        }
        guard let candidate = matchTarget(for: rule.kind, target: target,
                                          alternateHost: alternateHost) else { return false }
        return matches(rule.kind, target: candidate, domainMatcher: domainMatcher)
    }

    private static func matchTarget(for kind: RuleKind, target: RequestTarget,
                                    alternateHost: String?) -> RequestTarget? {
        switch kind {
        case .domain, .domainSuffix, .domainKeyword, .domainWildcard:
            guard let alternateHost else { return target }
            return RequestTarget(host: alternateHost, port: target.port,
                                 protocolName: target.protocolName,
                                 sourceHost: target.sourceHost,
                                 sourcePort: target.sourcePort,
                                 inboundPort: target.inboundPort,
                                 processName: target.processName)
        case .logicalAnd, .logicalOr, .logicalNot:
            return target
        case .ruleSet:
            return nil
        default:
            return target
        }
    }
}

package enum DomainPattern {
    private static let dotCharacterSet = CharacterSet(charactersIn: ".")

    package static func trimDotsAndLowercase(_ raw: String) -> String {
        raw.lowercased().trimmingCharacters(in: dotCharacterSet)
    }

    package static func any(_ patterns: [String], matches host: String) -> Bool {
        patterns.contains { matches($0, host: host) }
    }

    package static func matches(_ pattern: String, host: String) -> Bool {
        let needle = pattern.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !needle.isEmpty else { return false }
        let name = trimDotsAndLowercase(host)
        if needle.contains("*") || needle.contains("?") {
            return wildcard(needle, matches: name)
        }
        let suffix = trimDotsAndLowercase(needle)
        return name == suffix || name.hasSuffix("." + suffix)
    }

    package static func wildcard(_ pattern: String, matches host: String) -> Bool {
        let name = trimDotsAndLowercase(host)
        let raw = trimDotsAndLowercase(pattern)
        return glob(raw, matches: name)
    }

    private static func glob(_ pattern: String, matches value: String) -> Bool {
        func walk(_ p: String.Index, _ v: String.Index) -> Bool {
            var patternIndex = p
            var valueIndex = v
            while patternIndex < pattern.endIndex {
                let character = pattern[patternIndex]
                if character == "*" {
                    let next = pattern.index(after: patternIndex)
                    if next == pattern.endIndex { return true }
                    var probe = valueIndex
                    while probe <= value.endIndex {
                        if walk(next, probe) { return true }
                        if probe == value.endIndex { break }
                        probe = value.index(after: probe)
                    }
                    return false
                }
                if valueIndex == value.endIndex { return false }
                if character != "?" && character != value[valueIndex] { return false }
                patternIndex = pattern.index(after: patternIndex)
                valueIndex = value.index(after: valueIndex)
            }
            return valueIndex == value.endIndex
        }
        return walk(pattern.startIndex, value.startIndex)
    }
}

package enum IPCIDR {
    package static func contains(_ address: String, cidr: String) -> Bool {
        let pieces = cidr.split(separator: "/", maxSplits: 1).map(String.init)
        guard pieces.count == 2, let bits = Int(pieces[1]) else { return false }
        if pieces[0].contains(":"), (0...128).contains(bits) {
            return containsIPv6(address, network: pieces[0], bits: bits)
        }
        guard (0...32).contains(bits), let ip = ipv4Value(address),
              let network = ipv4Value(pieces[0]) else { return false }
        let mask: UInt32 = bits == 0 ? 0 : UInt32.max << UInt32(32 - bits)
        return (ip & mask) == (network & mask)
    }

    private static func ipv4Value(_ string: String) -> UInt32? {
        var address = in_addr()
        guard inet_pton(AF_INET, string, &address) == 1 else { return nil }
        return UInt32(bigEndian: address.s_addr)
    }

    private static func containsIPv6(_ rawAddress: String, network: String, bits: Int) -> Bool {
        let addressString = rawAddress.split(separator: "%", maxSplits: 1).first.map(String.init) ?? rawAddress
        var address = in6_addr()
        var networkAddress = in6_addr()
        guard inet_pton(AF_INET6, addressString, &address) == 1,
              inet_pton(AF_INET6, network, &networkAddress) == 1 else { return false }
        return withUnsafeBytes(of: &address) { addressBytes in
            withUnsafeBytes(of: &networkAddress) { networkBytes in
                let fullBytes = bits / 8
                for i in 0..<fullBytes where addressBytes[i] != networkBytes[i] {
                    return false
                }
                let remaining = bits % 8
                guard remaining > 0 else { return true }
                let mask = UInt8.max << UInt8(8 - remaining)
                return (addressBytes[fullBytes] & mask) == (networkBytes[fullBytes] & mask)
            }
        }
    }
}

public struct RoutingTable: Equatable {
    public let rules: [RoutingRule]
    public let ruleSetContents: [String: [RuleKind]]
    public let proxies: [String: ProxyPolicy]
    public let groups: [String: PolicyGroup]

    public init(rules: [RoutingRule], ruleSetContents: [String: [RuleKind]],
                proxies: [String: ProxyPolicy], groups: [String: PolicyGroup]) {
        self.rules = rules
        self.ruleSetContents = ruleSetContents
        self.proxies = proxies
        self.groups = groups
    }

    public func route(for target: RequestTarget, mode: OutboundMode, globalPolicy: String,
                      groupSelections: [String: String] = [:], alternateHost: String? = nil) -> ResolvedRoute {
        route(for: target, mode: mode, globalPolicy: globalPolicy,
              groupSelections: groupSelections, alternateHost: alternateHost,
              compiledSelection: .fallback, domainMatcher: nil)
    }

    package func route(for target: RequestTarget, mode: OutboundMode, globalPolicy: String,
                       groupSelections: [String: String], alternateHost: String?,
                       compiledSelection: RoutingRuleSelection,
                       domainMatcher: RoutingDomainMatcher?) -> ResolvedRoute {
        switch mode {
        case .direct:
            return .direct("DIRECT")
        case .proxy:
            return resolvePolicy(globalPolicy, target: target,
                                 groupSelections: groupSelections, visited: [])
        case .rule:
            switch compiledSelection {
            case .matched(let index) where rules.indices.contains(index):
                return resolvePolicy(rules[index].policy, target: target,
                                     groupSelections: groupSelections, visited: [])
            case .noMatch: return .direct("DIRECT")
            case .matched, .fallback, .invalid: break
            }
            for rule in rules {
                guard RoutingRuleMatcher.matches(rule, target: target, alternateHost: alternateHost,
                                                  ruleSetContents: ruleSetContents,
                                                  domainMatcher: domainMatcher) else { continue }
                return resolvePolicy(rule.policy, target: target,
                                     groupSelections: groupSelections, visited: [])
            }
            return .direct("DIRECT")
        }
    }

    public func interpretedRuleIndex(for target: RequestTarget, alternateHost: String? = nil) -> Int? {
        interpretedRuleIndex(for: target, alternateHost: alternateHost, domainMatcher: nil)
    }

    package func interpretedRuleIndex(for target: RequestTarget, alternateHost: String?,
                                      domainMatcher: RoutingDomainMatcher?) -> Int? {
        rules.firstIndex {
            RoutingRuleMatcher.matches($0, target: target, alternateHost: alternateHost,
                                       ruleSetContents: ruleSetContents, domainMatcher: domainMatcher)
        }
    }

    public func resolvePolicy(_ policy: String, target: RequestTarget,
                              groupSelections: [String: String] = [:]) -> ResolvedRoute {
        resolvePolicy(policy, target: target, groupSelections: groupSelections, visited: [])
    }

    private func resolvePolicy(_ rawName: String, target: RequestTarget,
                               groupSelections: [String: String],
                               visited: Set<String>) -> ResolvedRoute {
        let name = canonicalName(rawName)
        if visited.contains(name) { return .reject("Policy loop: \(name)") }

        if let group = groups[name] {
            var next: String?
            if let selected = groupSelections[name], group.members.contains(selected) {
                next = Self.extractSubnetTargetPolicy(selected)
            } else if group.kind == .subnet, !group.members.isEmpty {
                next = resolveSubnetMember(group: group, sourceHost: target.sourceHost)
            } else if group.kind == .loadBalance, !group.members.isEmpty {
                let useJump = group.parameters["strategy"]?.lowercased() == "jump"
                let idx = useJump
                    ? jumpConsistentIndex(for: target, count: group.members.count)
                    : stableIndex(for: target, count: group.members.count)
                next = group.members[idx]
            } else if group.kind == .smart, !group.members.isEmpty {
                next = resolveSmartMember(group: group)
            } else {
                next = group.members.first
            }
            guard let member = next else { return .reject("Empty group: \(name)") }
            var newVisited = visited
            newVisited.insert(name)
            return resolvePolicy(member, target: target,
                                 groupSelections: groupSelections, visited: newVisited)
        }

        guard let proxy = proxies[name] else { return .reject("Unknown: \(rawName)") }
        switch proxy.kind {
        case .direct: return .direct(proxy.name)
        case .reject: return .reject(proxy.name)
        case .http: return .http(proxy, proxy.name)
        case .socks5: return .socks5(proxy, proxy.name)
        case .native:
            switch proxy.adapterType?.lowercased() {
            case "http", "https": return .http(proxy, proxy.name)
            case "socks5", "socks5-tls": return .socks5(proxy, proxy.name)
            default: break
            }
            return .native(proxy, proxy.name)
        case .external: return .reject("Adapter not running: \(proxy.name)")
        }
    }

    private static func extractSubnetTargetPolicy(_ rawMember: String) -> String {
        guard let eq = rawMember.firstIndex(of: "=") else {
            return rawMember.trimmingCharacters(in: .whitespacesAndNewlines)
        }
        let rhs = rawMember[rawMember.index(after: eq)...].trimmingCharacters(in: .whitespacesAndNewlines)
        return rhs.isEmpty ? rawMember.trimmingCharacters(in: .whitespacesAndNewlines) : rhs
    }

    private func resolveSubnetMember(group: PolicyGroup, sourceHost: String?) -> String? {
        var fallbackPolicy: String? = group.parameters["default"]?.trimmingCharacters(in: .whitespacesAndNewlines)
        var firstCandidate: String?
        for raw in group.members {
            let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !trimmed.isEmpty else { continue }
            if let eq = trimmed.firstIndex(of: "=") {
                let condition = trimmed[..<eq].trimmingCharacters(in: .whitespacesAndNewlines)
                let policy = trimmed[trimmed.index(after: eq)...].trimmingCharacters(in: .whitespacesAndNewlines)
                guard !policy.isEmpty else { continue }
                if firstCandidate == nil { firstCandidate = policy }
                if condition.caseInsensitiveCompare("default") == .orderedSame {
                    fallbackPolicy = policy
                    continue
                }
                if let sourceHost, !sourceHost.isEmpty {
                    let cidr = condition.contains("/") ? condition : (condition.contains(":") ? "\(condition)/128" : "\(condition)/32")
                    if IPCIDR.contains(sourceHost, cidr: cidr) {
                        return policy
                    }
                }
            } else {
                if firstCandidate == nil { firstCandidate = trimmed }
            }
        }
        return fallbackPolicy ?? firstCandidate ?? group.members.first
    }

    private func resolveSmartMember(group: PolicyGroup) -> String? {
        guard let prioritySpec = group.parameters["policy-priority"], !prioritySpec.isEmpty else {
            return group.members.first
        }
        var weights: [String: Double] = [:]
        for item in prioritySpec.split(whereSeparator: { $0 == ";" || $0 == "," }) {
            let pair = item.split(separator: ":", maxSplits: 1)
            guard pair.count == 2 else { continue }
            let key = pair[0].trimmingCharacters(in: .whitespacesAndNewlines)
            if let factor = Double(pair[1].trimmingCharacters(in: .whitespacesAndNewlines)),
               factor.isFinite, factor > 0 {
                weights[key] = factor
            }
        }
        guard !weights.isEmpty else { return group.members.first }
        return group.members.min { lhs, rhs in
            let w1 = weights[lhs] ?? 1.0
            let w2 = weights[rhs] ?? 1.0
            return w1 > w2
        } ?? group.members.first
    }

    private func canonicalName(_ name: String) -> String {
        if proxies[name] != nil || groups[name] != nil { return name }
        if name.uppercased() == "DIRECT" { return "DIRECT" }
        if name.uppercased().hasPrefix("REJECT") { return "REJECT" }
        return name
    }

    private func fnv1aKeyHash(for target: RequestTarget) -> UInt64 {
        var hash: UInt64 = 14_695_981_039_346_656_037
        let prime: UInt64 = 1_099_511_628_211
        let isAsciiHost = target.host.utf8.allSatisfy { $0 < 0x80 }
        if isAsciiHost {
            for byte in target.host.utf8 {
                let lower = (byte >= 65 && byte <= 90) ? (byte &+ 32) : byte
                hash = (hash ^ UInt64(lower)) &* prime
            }
        } else {
            for byte in target.host.lowercased().utf8 {
                hash = (hash ^ UInt64(byte)) &* prime
            }
        }
        hash = (hash ^ 58) &* prime
        var portVal = target.port
        if portVal == 0 {
            hash = (hash ^ 48) &* prime
        } else {
            var digits: (UInt8, UInt8, UInt8, UInt8, UInt8) = (0, 0, 0, 0, 0)
            var len = 0
            withUnsafeMutableBytes(of: &digits) { buf in
                while portVal > 0 {
                    buf[len] = UInt8(48 + (portVal % 10))
                    portVal /= 10
                    len += 1
                }
                while len > 0 {
                    len -= 1
                    hash = (hash ^ UInt64(buf[len])) &* prime
                }
            }
        }
        hash = (hash ^ 47) &* prime
        for byte in target.protocolName.utf8 {
            hash = (hash ^ UInt64(byte)) &* prime
        }
        return hash
    }

    private func stableIndex(for target: RequestTarget, count: Int) -> Int {
        guard count > 1 else { return 0 }
        return Int(fnv1aKeyHash(for: target) % UInt64(count))
    }

    private func jumpConsistentIndex(for target: RequestTarget, count: Int) -> Int {
        guard count > 1 else { return 0 }
        var z = fnv1aKeyHash(for: target)
        z = (z ^ (z >> 30)) &* 0xbf58476d1ce4e5b9
        z = (z ^ (z >> 27)) &* 0x94d049bb133111eb
        var key = z ^ (z >> 31)
        var b: Int64 = -1
        var j: Int64 = 0
        let buckets = Int64(count)
        while j < buckets {
            b = j
            key = key &* 2862933555777941757 &+ 1
            j = Int64(Double(b + 1) * (Double(1 << 31) / Double((key >> 33) + 1)))
        }
        return Int(max(0, b))
    }
}
