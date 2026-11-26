import Foundation

extension Profile {
    /// Serializes the in-memory UI `Profile` and active group overrides into a canonical
    /// Surge-compatible `.conf` payload consumed directly by `HajimiEngineCAPI`.
    func toUnifiedEngineConfigText(globalPolicy: String,
                                   groupSelections: [String: String]) -> String {
        var lines: [String] = []
        lines.append("[General]")
        lines.append("http-listen = \(httpListen.host):\(httpListen.port)")
        lines.append("socks5-listen = \(socksListen.host):\(socksListen.port)")
        if let ctrl = externalController ?? httpAPI {
            lines.append("external-controller = \(ctrl.host):\(ctrl.port)")
        }
        if let secret = externalControllerKey ?? httpAPIKey, !secret.isEmpty {
            lines.append("secret = \(secret)")
        }
        let tradDns = traditionalDNSServers
        if !tradDns.isEmpty {
            lines.append("dns-server = " + tradDns.joined(separator: ", "))
        }
        let encDns = effectiveEncryptedDNSServers
        if !encDns.isEmpty {
            lines.append("encrypted-dns-server = " + encDns.joined(separator: ", "))
        }
        if fakeIPEnabled {
            lines.append("enhanced-mode = fake-ip")
        }
        if !alwaysRealIP.isEmpty {
            lines.append("always-real-ip = " + alwaysRealIP.joined(separator: ", "))
        }
        if !proxyBypassDomains.isEmpty {
            lines.append("skip-proxy = " + proxyBypassDomains.joined(separator: ", "))
        }
        if !tunExcludedRoutes.isEmpty {
            lines.append("tun-excluded-routes = " + tunExcludedRoutes.joined(separator: ", "))
        }
        lines.append("")

        lines.append("[Proxy]")
        let orderedProxies = proxyOrder.isEmpty ? proxies.keys.sorted() : proxyOrder
        for name in orderedProxies {
            guard let p = proxies[name] else { continue }
            if p.kind == .direct || p.kind == .reject { continue }
            let draft = SurgeProxyDraft(policy: p)
            if let def = try? SurgeProfileDocument.definition(for: draft) {
                lines.append("\(p.name) = \(def)")
            } else if let host = p.host, !host.isEmpty, let port = p.port, port > 0 {
                var parts = ["\(p.name) = \(draft.type)", host, String(port)]
                for k in draft.parameters.keys.sorted() {
                    if let v = draft.parameters[k] {
                        parts.append("\(k)=\(v)")
                    }
                }
                lines.append(parts.joined(separator: ", "))
            }
        }
        lines.append("")

        lines.append("[Proxy Group]")
        let orderedGroups = groupOrder.isEmpty ? groups.keys.sorted() : groupOrder
        for gName in orderedGroups {
            guard var g = groups[gName] else { continue }
            if let sel = groupSelections[gName], let idx = g.members.firstIndex(of: sel), idx > 0 {
                g.members.remove(at: idx)
                g.members.insert(sel, at: 0)
            }
            let groupDraft = SurgePolicyGroupDraft(group: g)
            if let def = try? SurgeProfileDocument.definition(for: groupDraft) {
                lines.append("\(g.name) = \(def)")
            }
        }
        lines.append("")

        lines.append("[Rule]")
        var hasFinal = false
        for rule in rules {
            if case .final = rule.kind {
                hasFinal = true
                lines.append("FINAL, \(rule.policy)")
            } else if let expr = Self.formatRuleCondition(rule.kind) {
                lines.append("\(expr), \(rule.policy)")
            }
        }
        if !hasFinal {
            lines.append("FINAL, \(globalPolicy.isEmpty ? "DIRECT" : globalPolicy)")
        }
        return lines.joined(separator: "\n") + "\n"
    }

    static func serializeRuleKinds(_ kinds: [RuleKind]) -> String {
        var lines: [String] = []
        lines.reserveCapacity(kinds.count)
        for k in kinds {
            if let expr = formatRuleCondition(k) {
                lines.append(expr)
            }
        }
        return lines.joined(separator: "\n")
    }

    private static func formatPortRange(_ range: ClosedRange<UInt16>) -> String {
        range.lowerBound == range.upperBound
            ? String(range.lowerBound)
            : "\(range.lowerBound)-\(range.upperBound)"
    }

    private static func formatRuleCondition(_ kind: RuleKind) -> String? {
        switch kind {
        case .domain(let v):
            return "DOMAIN,\(v)"
        case .domainSuffix(let v):
            return "DOMAIN-SUFFIX,\(v)"
        case .domainKeyword(let v):
            return "DOMAIN-KEYWORD,\(v)"
        case .domainWildcard(let v):
            return "DOMAIN-WILDCARD,\(v)"
        case .ipCIDR(let v):
            return v.contains(":") ? "IP-CIDR6,\(v)" : "IP-CIDR,\(v)"
        case .destinationPort(let range):
            return "DEST-PORT,\(formatPortRange(range))"
        case .sourceIPCIDR(let v):
            return "SRC-IP-CIDR,\(v)"
        case .sourcePort(let range):
            return "SRC-PORT,\(formatPortRange(range))"
        case .inboundPort(let range):
            return "IN-PORT,\(formatPortRange(range))"
        case .protocolName(let proto):
            return "PROTOCOL,\(proto)"
        case .geoIP(let v):
            return "GEOIP,\(v)"
        case .ipASN(let v):
            return "IP-ASN,\(v)"
        case .processName(let v):
            return "PROCESS-NAME,\(v)"
        case .logicalAnd(let children):
            let subs = children.compactMap { formatRuleCondition($0).map { "(\($0))" } }
            return subs.isEmpty ? nil : "AND,(\(subs.joined(separator: ",")))"
        case .logicalOr(let children):
            let subs = children.compactMap { formatRuleCondition($0).map { "(\($0))" } }
            return subs.isEmpty ? nil : "OR,(\(subs.joined(separator: ",")))"
        case .logicalNot(let child):
            guard let sub = formatRuleCondition(child) else { return nil }
            return "NOT,((\(sub)))"
        case .ruleSet(let ref):
            return "RULE-SET,\(ref.location)"
        case .final:
            return nil
        }
    }
}
