#pragma once

#include "../HajimiProtocolsCXX/Runtime.hpp"
#include "../HajimiRoutingCXX/include/HajimiRoutingCXX.h"
#include <cstdint>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

namespace hajimi::engine {

enum class PolicyGroupKind : uint8_t {
    Select = 0,
    UrlTest = 1,
    Fallback = 2,
    LoadBalance = 3,
    SmartUCB1 = 4,
};

struct PolicyGroup {
    std::string name;
    PolicyGroupKind kind = PolicyGroupKind::Select;
    std::vector<std::string> staticMembers;
    std::vector<std::string> members;
    std::vector<std::string> useProviders;
    std::vector<std::string> includeOtherGroups;
    bool includeAllProxies = false;
    std::string includeFilterRegex;
    std::string excludeFilterRegex;
    std::string excludeTypeFilter;
    std::string selected;
    std::string testUrl = "http://www.gstatic.com/generate_204";
    uint32_t intervalSeconds = 300;
    uint32_t toleranceMs = 50;
};

enum class ExtraRuleKind : uint8_t {
    Compiled = 0,     // Evaluated via HJCompiledRules fast path
    ProcessName = 1,  // Matched against normalized .exe / stem / full path
    DomainWildcard = 2,
    ProtocolName = 3,
};

struct ParsedRule {
    ExtraRuleKind extraKind = ExtraRuleKind::Compiled;
    std::string rawType;
    std::string pattern;
    std::string policy;
    bool noResolve = false;
};

struct RuleSetReference {
    std::string key;
    std::string url;
    std::string policy;
    std::string behavior = "classical"; // classical | domain | ipcidr
    std::string format = "text";        // text | yaml | mrs
};

struct NodeProviderReference {
    std::string key;
    std::string url;
    uint32_t intervalSeconds = 3600;
};

struct DnsProfileSettings {
    std::vector<std::string> nameservers{"1.1.1.1", "8.8.8.8"};
    std::vector<std::string> encryptedUpstreams{"https://1.1.1.1/dns-query", "tls://1.1.1.1:853"};
    bool fakeIpEnabled = true;
    bool ipv6Enabled = false;
    std::unordered_map<std::string, std::string> staticHosts;
};

struct TunProfileSettings {
    std::vector<std::string> excludedRoutes;
    std::vector<std::string> includedRoutes;
    uint32_t mtu = 1400;
};

struct EngineProfile {
    std::string name = "Default";
    uint16_t httpPort = 0;
    uint16_t socksPort = 0;
    uint16_t externalControllerPort = 0;
    std::string externalControllerKey;
    std::vector<std::string> skipProxyDomains{"localhost", "127.0.0.1", "*.local", "10.*", "192.168.*"};

    std::unordered_map<std::string, Node> nodes;
    std::vector<std::string> nodeOrder;
    std::vector<std::string> baseNodeOrder;
    std::unordered_map<std::string, Node> baseNodes;

    std::vector<NodeProviderReference> nodeProviders;
    std::unordered_map<std::string, std::vector<Node>> providerNodes;

    std::unordered_map<std::string, PolicyGroup> groups;
    std::vector<std::string> groupOrder;

    // `baseRules` stores the original profile rules (including `RULE-SET`, `DOMAIN-SET`, and `GEOIP` placeholders);
    // `rules` stores the expanded active rules compiled into `compiledRules`.
    std::vector<ParsedRule> baseRules;
    std::vector<ParsedRule> rules;
    std::vector<RuleSetReference> ruleSets;
    std::unordered_map<std::string, std::string> ruleSetContents;
    std::string finalPolicy = "DIRECT";

    DnsProfileSettings dns;
    TunProfileSettings tun;

    std::shared_ptr<HJCompiledRules> compiledRules;
    std::vector<std::string> compiledOrdinalPolicies;

    /// Normalizes a Windows or POSIX process path/name (`C:\Program Files\Google\Chrome\Application\chrome.exe` -> `chrome`)
    static std::string normalizeProcessStem(const std::string &processPathOrName);

    /// Matches a `PROCESS-NAME` or `PROCESS-PATH` pattern against a candidate process path or executable name.
    static bool matchesProcessRule(const std::string &pattern, const std::string &candidatePathOrName);

    /// Evaluates ordered routing rules (combining C++ compiled suffix/CIDR/port rules and extra runtime rules).
    std::string evaluateRoute(const std::string &host,
                              uint16_t dstPort,
                              const std::string &protocolName,
                              const std::string &processPathOrName,
                              const std::string &sourceIp = "") const;
};

class ProfileConfigParser {
public:
    /// Auto-detects and parses Surge `.conf`, Clash/Mihomo YAML, or Base64/plain share-link subscriptions.
    static bool parseText(const std::string &text, EngineProfile &outProfile, std::string &outError);

    /// Reads UTF-8 file path safely on Windows (wide path) and POSIX, then parses it.
    static bool parseFileUTF8(const std::string &utf8Path, EngineProfile &outProfile, std::string &outError);

    /// Parses a single share link (`ss://`, `ssr://`, `trojan://`, `vless://`, `vmess://`, `hy2://`, `hysteria://`, `tuic://`, `wireguard://`, `snell://`, `mieru://`, `sudoku://`, `trusttunnel://`, `anytls://`, `socks5://`, `http://`).
    static bool parseShareLink(const std::string &uri, Node &outNode);

    /// Recomputes dynamic policy group membership (`include-all-proxies`, `use:`, `include-other-group`, regex `filter` / `exclude-filter`, `exclude-type`).
    static void recomputeDynamicGroups(EngineProfile &profile);

    /// Injects or updates an external `proxy-provider` / `policy-path` payload (Clash YAML, Base64, or share links) and recomputes dynamic policy groups.
    static size_t updateNodeProvider(EngineProfile &profile, const std::string &keyOrUrl, const std::string &content);

    /// Injects or updates an external `RULE-SET` / `DOMAIN-SET` / `GEOSITE` / `GEOIP:CN` payload and recompiles `EngineProfile::compiledRules`.
    /// Returns the total expanded rule count after recompilation.
    static size_t updateRuleSet(EngineProfile &profile, const std::string &keyOrUrl, const std::string &content);
};

} // namespace hajimi::engine
