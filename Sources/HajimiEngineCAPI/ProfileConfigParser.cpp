#include "ProfileConfigParser.hpp"
#include "../HajimiProtocolsCXX/PlatformCompat.hpp"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <regex>
#include <sstream>
#include <unordered_set>

namespace hajimi::engine {

namespace {

std::string trimCopy(std::string s) {
    size_t b = 0;
    while (b < s.size() && (s[b] == ' ' || s[b] == '\t' || s[b] == '\r' || s[b] == '\n')) ++b;
    size_t e = s.size();
    while (e > b && (s[e - 1] == ' ' || s[e - 1] == '\t' || s[e - 1] == '\r' || s[e - 1] == '\n')) --e;
    return s.substr(b, e - b);
}

std::string lowerAscii(std::string s) {
    for (char &c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

std::string upperAscii(std::string s) {
    for (char &c : s) c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
    return s;
}

std::string unquoteCopy(std::string s) {
    s = trimCopy(std::move(s));
    if (s.size() >= 2 && ((s.front() == '"' && s.back() == '"') || (s.front() == '\'' && s.back() == '\''))) {
        char q = s.front();
        std::string inner = s.substr(1, s.size() - 2);
        if (q == '\'') {
            std::string out;
            out.reserve(inner.size());
            for (size_t i = 0; i < inner.size(); ++i) {
                if (inner[i] == '\'' && i + 1 < inner.size() && inner[i + 1] == '\'') {
                    out.push_back('\'');
                    ++i;
                } else {
                    out.push_back(inner[i]);
                }
            }
            return out;
        }
        std::string out;
        out.reserve(inner.size());
        for (size_t i = 0; i < inner.size(); ++i) {
            if (inner[i] == '\\' && i + 1 < inner.size()) {
                char nxt = inner[++i];
                switch (nxt) {
                    case 'n': out.push_back('\n'); break;
                    case 'r': out.push_back('\r'); break;
                    case 't': out.push_back('\t'); break;
                    default: out.push_back(nxt); break;
                }
            } else {
                out.push_back(inner[i]);
            }
        }
        return out;
    }
    return s;
}

bool isTruthyValue(const std::string &v) {
    const std::string low = lowerAscii(trimCopy(v));
    return low == "1" || low == "true" || low == "yes" || low == "on";
}

std::string normalizeProxyProtocolType(const std::string &rawType, bool &impliesTls) {
    impliesTls = false;
    const std::string low = lowerAscii(trimCopy(rawType));
    if (low == "shadowsocks" || low == "custom") return "ss";
    if (low == "shadowsocksr") return "ssr";
    if (low == "hy2") return "hysteria2";
    if (low == "hy" || low == "hysteria1") return "hysteria";
    if (low == "tuic-v5" || low == "tuicv5") return "tuic";
    if (low == "wg") return "wireguard";
    if (low == "trust-tunnel") return "trusttunnel";
    if (low == "socks5-tls" || low == "socks5+tls") {
        impliesTls = true;
        return "socks5";
    }
    if (low == "https") {
        impliesTls = true;
        return "http";
    }
    if (low == "socks") return "socks5";
    return low;
}

uint16_t extractFirstPortFromRange(const std::string &rawRange) {
    std::string s = trimCopy(unquoteCopy(rawRange));
    if (s.empty()) return 0;
    auto comma = s.find(',');
    if (comma != std::string::npos) s = trimCopy(s.substr(0, comma));
    auto slash = s.find('/');
    if (slash != std::string::npos) s = trimCopy(s.substr(0, slash));
    auto dash = s.find('-');
    if (dash != std::string::npos) s = trimCopy(s.substr(0, dash));
    char *end = nullptr;
    unsigned long v = std::strtoul(s.c_str(), &end, 10);
    if (end == s.c_str() || v == 0 || v > 65535UL) return 0;
    return static_cast<uint16_t>(v);
}

std::string ensureUniqueNodeName(const EngineProfile &profile, const std::string &desired) {
    std::string base = trimCopy(desired);
    if (base.empty()) base = "Node";
    if (profile.nodes.find(base) == profile.nodes.end() &&
        profile.baseNodes.find(base) == profile.baseNodes.end()) {
        return base;
    }
    for (int suffix = 2; suffix < 10000; ++suffix) {
        std::string cand = base + " #" + std::to_string(suffix);
        if (profile.nodes.find(cand) == profile.nodes.end() &&
            profile.baseNodes.find(cand) == profile.baseNodes.end()) {
            return cand;
        }
    }
    return base;
}

std::string stripInlineLineComment(const std::string &line, bool allowSlashSlash = true) {
    bool inSingle = false;
    bool inDouble = false;
    for (size_t i = 0; i < line.size(); ++i) {
        char c = line[i];
        if (c == '\\' && inDouble && i + 1 < line.size()) {
            ++i;
            continue;
        }
        if (c == '\'' && !inDouble) {
            if (inSingle && i + 1 < line.size() && line[i + 1] == '\'') {
                ++i;
                continue;
            }
            inSingle = !inSingle;
            continue;
        }
        if (c == '"' && !inSingle) {
            inDouble = !inDouble;
            continue;
        }
        if (!inSingle && !inDouble) {
            if (c == '#' && (i == 0 || line[i - 1] == ' ' || line[i - 1] == '\t')) {
                return line.substr(0, i);
            }
            if (allowSlashSlash && c == '/' && i + 1 < line.size() && line[i + 1] == '/' &&
                (i == 0 || line[i - 1] == ' ' || line[i - 1] == '\t')) {
                return line.substr(0, i);
            }
        }
    }
    return line;
}

std::vector<std::string> splitCsvRespectingQuotes(const std::string &line) {
    std::vector<std::string> parts;
    std::string cur;
    bool inQuotes = false;
    char quoteCh = 0;
    int parenDepth = 0;
    int bracketDepth = 0;
    for (size_t i = 0; i < line.size(); ++i) {
        char c = line[i];
        if (inQuotes) {
            if (c == '\\' && quoteCh == '"' && i + 1 < line.size()) {
                cur.push_back(c);
                cur.push_back(line[++i]);
                continue;
            }
            if (c == quoteCh) {
                inQuotes = false;
            }
            cur.push_back(c);
            continue;
        }
        if (c == '"' || c == '\'') {
            inQuotes = true;
            quoteCh = c;
            cur.push_back(c);
        } else if (c == '(') {
            ++parenDepth;
            cur.push_back(c);
        } else if (c == ')' && parenDepth > 0) {
            --parenDepth;
            cur.push_back(c);
        } else if (c == '[') {
            ++bracketDepth;
            cur.push_back(c);
        } else if (c == ']' && bracketDepth > 0) {
            --bracketDepth;
            cur.push_back(c);
        } else if (c == ',' && parenDepth == 0 && bracketDepth == 0) {
            parts.push_back(trimCopy(cur));
            cur.clear();
        } else {
            cur.push_back(c);
        }
    }
    parts.push_back(trimCopy(cur));
    return parts;
}

std::string percentDecode(const std::string &s) {
    std::string out;
    out.reserve(s.size());
    for (size_t i = 0; i < s.size(); ++i) {
        if (s[i] == '%' && i + 2 < s.size() &&
            std::isxdigit(static_cast<unsigned char>(s[i + 1])) &&
            std::isxdigit(static_cast<unsigned char>(s[i + 2]))) {
            char hex[3] = {s[i + 1], s[i + 2], 0};
            out.push_back(static_cast<char>(std::strtol(hex, nullptr, 16)));
            i += 2;
        } else if (s[i] == '+') {
            out.push_back(' ');
        } else {
            out.push_back(s[i]);
        }
    }
    return out;
}

std::unordered_map<std::string, std::string> parseQueryString(const std::string &qs) {
    std::unordered_map<std::string, std::string> out;
    size_t pos = 0;
    while (pos < qs.size()) {
        size_t amp = qs.find('&', pos);
        if (amp == std::string::npos) amp = qs.size();
        std::string kv = qs.substr(pos, amp - pos);
        if (!kv.empty()) {
            size_t eq = kv.find('=');
            if (eq == std::string::npos) {
                out[lowerAscii(percentDecode(kv))] = "1";
            } else {
                out[lowerAscii(percentDecode(kv.substr(0, eq)))] = percentDecode(kv.substr(eq + 1));
            }
        }
        pos = amp + 1;
    }
    return out;
}

bool decodeBase64Flexible(std::string input, std::string &decoded) {
    input.erase(std::remove_if(input.begin(), input.end(), [](unsigned char c) {
        return c == '\r' || c == '\n' || c == ' ' || c == '\t';
    }), input.end());
    if (input.empty()) return false;
    auto b64Val = [](unsigned char c) -> int {
        if (c >= 'A' && c <= 'Z') return c - 'A';
        if (c >= 'a' && c <= 'z') return c - 'a' + 26;
        if (c >= '0' && c <= '9') return c - '0' + 52;
        if (c == '+' || c == '-') return 62;
        if (c == '/' || c == '_') return 63;
        return -1;
    };
    while (!input.empty() && input.back() == '=') input.pop_back();
    if (input.empty() || (input.size() % 4) == 1) return false;
    decoded.clear();
    decoded.reserve((input.size() * 3) / 4);
    uint32_t acc = 0;
    int bits = 0;
    for (unsigned char c : input) {
        int v = b64Val(c);
        if (v < 0) return false;
        acc = (acc << 6) | static_cast<uint32_t>(v);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            decoded.push_back(static_cast<char>((acc >> bits) & 0xFFu));
        }
    }
    return !decoded.empty();
}

bool looksLikeBase64SubscriptionPayload(const std::string &trimmed) {
    if (trimmed.size() < 20) return false;
    if (trimmed.find("://") != std::string::npos ||
        trimmed.find("proxies:") != std::string::npos ||
        trimmed.find("proxy-groups:") != std::string::npos ||
        trimmed.find("[Proxy]") != std::string::npos ||
        trimmed.find("[General]") != std::string::npos) {
        return false;
    }
    size_t validChars = 0;
    for (unsigned char c : trimmed) {
        if (c == '\r' || c == '\n' || c == ' ' || c == '\t') continue;
        if (std::isalnum(c) || c == '+' || c == '/' || c == '=' || c == '-' || c == '_') {
            ++validChars;
        } else {
            return false;
        }
    }
    return validChars >= 20;
}

std::string jsonExtractString(const std::string &json, const std::string &key) {
    const std::string needle = "\"" + key + "\"";
    size_t pos = json.find(needle);
    if (pos == std::string::npos) return {};
    pos = json.find(':', pos + needle.size());
    if (pos == std::string::npos) return {};
    ++pos;
    while (pos < json.size() && std::isspace(static_cast<unsigned char>(json[pos]))) ++pos;
    if (pos >= json.size()) return {};
    if (json[pos] == '"') {
        ++pos;
        std::string out;
        while (pos < json.size() && json[pos] != '"') {
            if (json[pos] == '\\' && pos + 1 < json.size()) {
                ++pos;
            }
            out.push_back(json[pos++]);
        }
        return out;
    }
    size_t end = pos;
    while (end < json.size() && json[end] != ',' && json[end] != '}' &&
           !std::isspace(static_cast<unsigned char>(json[end]))) {
        ++end;
    }
    std::string tok = json.substr(pos, end - pos);
    return (tok == "null") ? std::string{} : tok;
}

bool splitHostPort(const std::string &hostPort, std::string &hostOut, uint16_t &portOut) {
    std::string s = trimCopy(hostPort);
    if (s.empty()) return false;
    std::string portStr;
    if (s.front() == '[') {
        auto rb = s.find(']');
        if (rb == std::string::npos || rb + 2 > s.size() || s[rb + 1] != ':') return false;
        hostOut = s.substr(1, rb - 1);
        portStr = s.substr(rb + 2);
    } else {
        auto colon = s.rfind(':');
        if (colon == std::string::npos) return false;
        hostOut = s.substr(0, colon);
        portStr = s.substr(colon + 1);
    }
    portOut = extractFirstPortFromRange(portStr);
    return !hostOut.empty() && portOut != 0;
}

bool parsePortRangeString(const std::string &s, uint16_t &loOut, uint16_t &hiOut) {
    std::string clean = trimCopy(s);
    if (clean.empty()) return false;
    auto dash = clean.find('-');
    if (dash == std::string::npos) {
        char *end = nullptr;
        unsigned long p = std::strtoul(clean.c_str(), &end, 10);
        if (end != clean.c_str() + clean.size() || p > 65535UL) return false;
        loOut = hiOut = static_cast<uint16_t>(p);
        return true;
    }
    std::string a = trimCopy(clean.substr(0, dash));
    std::string b = trimCopy(clean.substr(dash + 1));
    char *e1 = nullptr;
    char *e2 = nullptr;
    unsigned long p1 = std::strtoul(a.c_str(), &e1, 10);
    unsigned long p2 = std::strtoul(b.c_str(), &e2, 10);
    if (e1 != a.c_str() + a.size() || e2 != b.c_str() + b.size() || p1 > 65535UL || p2 > 65535UL || p1 > p2) {
        return false;
    }
    loOut = static_cast<uint16_t>(p1);
    hiOut = static_cast<uint16_t>(p2);
    return true;
}

bool wildcardMatchCaseInsensitive(const std::string &pattern, const std::string &candidate) {
    const std::string p = lowerAscii(pattern);
    const std::string s = lowerAscii(candidate);
    size_t pi = 0, si = 0, starIdx = std::string::npos, matchIdx = 0;
    while (si < s.size()) {
        if (pi < p.size() && (p[pi] == '?' || p[pi] == s[si])) {
            ++pi;
            ++si;
        } else if (pi < p.size() && p[pi] == '*') {
            starIdx = pi++;
            matchIdx = si;
        } else if (starIdx != std::string::npos) {
            pi = starIdx + 1;
            si = ++matchIdx;
        } else {
            return false;
        }
    }
    while (pi < p.size() && p[pi] == '*') ++pi;
    return pi == p.size();
}

bool safeRegexMatchName(const std::string &rawExpr, const std::string &candidate) {
    std::string expr = unquoteCopy(trimCopy(rawExpr));
    if (expr.empty()) return true;

    // Strip leading/inline `(?i)` flags unsupported by ECMAScript std::regex (we pass icase explicitly)
    std::string cleaned;
    cleaned.reserve(expr.size());
    for (size_t i = 0; i < expr.size();) {
        if (expr.compare(i, 4, "(?i)") == 0) {
            i += 4;
            continue;
        }
        cleaned.push_back(expr[i++]);
    }
    if (cleaned.empty()) return true;

    try {
        std::regex re(cleaned, std::regex::ECMAScript | std::regex::icase);
        if (std::regex_search(candidate, re)) return true;
    } catch (...) {
        // Fallback below for PCRE lookarounds or non-ECMAScript tokens
    }

    // Fallback: split top-level `|` alternation tokens and perform case-insensitive substring matching
    const std::string candLow = lowerAscii(candidate);
    int paren = 0;
    size_t start = 0;
    bool anyToken = false;
    auto checkBranch = [&](std::string branch) -> bool {
        while (!branch.empty() && (branch.front() == '^' || branch.front() == '(')) branch.erase(branch.begin());
        while (!branch.empty() && (branch.back() == '$' || branch.back() == ')')) branch.pop_back();
        if (branch.compare(0, 2, ".*") == 0) branch.erase(0, 2);
        if (branch.size() >= 2 && branch.compare(branch.size() - 2, 2, ".*") == 0) branch.erase(branch.size() - 2);
        branch = trimCopy(branch);
        if (branch.empty()) return false;
        anyToken = true;
        return candLow.find(lowerAscii(branch)) != std::string::npos;
    };

    for (size_t i = 0; i <= cleaned.size(); ++i) {
        if (i == cleaned.size() || (cleaned[i] == '|' && paren == 0)) {
            if (checkBranch(cleaned.substr(start, i - start))) return true;
            start = i + 1;
        } else if (cleaned[i] == '(') {
            ++paren;
        } else if (cleaned[i] == ')' && paren > 0) {
            --paren;
        }
    }
    return !anyToken && candLow.find(lowerAscii(cleaned)) != std::string::npos;
}

bool isExcludedByTypeFilter(const std::string &excludeTypeRaw, const std::string &nodeType) {
    if (excludeTypeRaw.empty() || nodeType.empty()) return false;
    const std::string target = lowerAscii(trimCopy(nodeType));
    std::string s = lowerAscii(unquoteCopy(excludeTypeRaw));
    for (char &c : s) {
        if (c == '|' || c == ';' || c == ' ') c = ',';
    }
    for (const auto &tok : splitCsvRespectingQuotes(s)) {
        bool dummyTls = false;
        std::string norm = normalizeProxyProtocolType(tok, dummyTls);
        if (!norm.empty() && norm == target) return true;
    }
    return false;
}

const char *kBuiltinLanRuleset =
    "DOMAIN-SUFFIX,local\n"
    "DOMAIN-SUFFIX,localhost\n"
    "DOMAIN-SUFFIX,lan\n"
    "DOMAIN-SUFFIX,home.arpa\n"
    "IP-CIDR,127.0.0.0/8\n"
    "IP-CIDR,10.0.0.0/8\n"
    "IP-CIDR,172.16.0.0/12\n"
    "IP-CIDR,192.168.0.0/16\n"
    "IP-CIDR,100.64.0.0/10\n"
    "IP-CIDR,169.254.0.0/16\n"
    "IP-CIDR6,::1/128\n"
    "IP-CIDR6,fc00::/7\n"
    "IP-CIDR6,fe80::/10\n";

const char *kBuiltinSystemRuleset =
    "DOMAIN-SUFFIX,local\n"
    "DOMAIN,captive.apple.com\n"
    "DOMAIN,time.apple.com\n"
    "DOMAIN,time.windows.com\n"
    "DOMAIN,www.msftconnecttest.com\n"
    "DOMAIN,dns.msftncsi.com\n";

bool isLooksLikeBareDomainToken(const std::string &s) {
    if (s.empty() || s.find('/') != std::string::npos || s.find(':') != std::string::npos ||
        s.find(' ') != std::string::npos) {
        return false;
    }
    bool hasAlpha = false;
    bool hasDot = false;
    for (unsigned char c : s) {
        if (std::isalpha(c)) hasAlpha = true;
        else if (c == '.') hasDot = true;
        else if (!std::isdigit(c) && c != '-' && c != '_' && c != '*' && c != '+') return false;
    }
    return hasAlpha && hasDot;
}

void parseRuleSetLinesInto(const std::string &content,
                           const std::string &policy,
                           const std::string &behaviorHint,
                           std::vector<ParsedRule> &outRules) {
    const std::string beh = lowerAscii(trimCopy(behaviorHint));
    std::istringstream iss(content);
    std::string raw;
    while (std::getline(iss, raw)) {
        if (!raw.empty() && raw.back() == '\r') raw.pop_back();
        if (raw.size() >= 3 &&
            static_cast<unsigned char>(raw[0]) == 0xEF &&
            static_cast<unsigned char>(raw[1]) == 0xBB &&
            static_cast<unsigned char>(raw[2]) == 0xBF) {
            raw.erase(0, 3);
        }
        std::string line = trimCopy(raw);
        if (line.empty() || line[0] == '#' || line[0] == ';') continue;
        if (line.size() >= 2 && line[0] == '/' && line[1] == '/') continue;
        if (line == "---" || line == "..." || line == "payload:" || line == "rules:") continue;

        if (line[0] == '-' && (line.size() == 1 || line[1] == ' ' || line[1] == '\t')) {
            line = trimCopy(line.substr(1));
        }
        // CRITICAL: Strip trailing `# comment` or ` // comment` BEFORE unquoting outer `'...'` or `"..."`!
        line = trimCopy(stripInlineLineComment(line, true));
        line = unquoteCopy(line);
        line = trimCopy(stripInlineLineComment(line, true));
        if (line.empty()) continue;

        // Shorthand 1: `+.example.com` or `.example.com` -> DOMAIN-SUFFIX
        if (line.size() > 2 && line[0] == '+' && line[1] == '.') {
            outRules.push_back(ParsedRule{ExtraRuleKind::Compiled, "DOMAIN-SUFFIX", line.substr(2), policy, false});
            continue;
        }
        if (line.size() > 1 && line[0] == '.') {
            outRules.push_back(ParsedRule{ExtraRuleKind::Compiled, "DOMAIN-SUFFIX", line.substr(1), policy, false});
            continue;
        }
        if (line.size() > 2 && line[0] == '*' && line[1] == '.' && line.find(',', 2) == std::string::npos) {
            outRules.push_back(ParsedRule{ExtraRuleKind::Compiled, "DOMAIN-SUFFIX", line.substr(2), policy, false});
            continue;
        }

        auto cols = splitCsvRespectingQuotes(line);
        if (cols.size() == 1) {
            const std::string &tok = cols[0];
            if (tok.find('/') != std::string::npos) {
                const char *rType = (tok.find(':') != std::string::npos) ? "IP-CIDR6" : "IP-CIDR";
                outRules.push_back(ParsedRule{ExtraRuleKind::Compiled, rType, tok, policy, true});
            } else if (beh == "domain" || isLooksLikeBareDomainToken(tok)) {
                if (tok.find('*') != std::string::npos || tok.find('?') != std::string::npos) {
                    outRules.push_back(ParsedRule{ExtraRuleKind::DomainWildcard, "DOMAIN-WILDCARD", tok, policy, false});
                } else {
                    outRules.push_back(ParsedRule{ExtraRuleKind::Compiled, "DOMAIN", tok, policy, false});
                }
            }
            continue;
        }

        std::string rType = upperAscii(cols[0]);
        if (rType == "HOST") rType = "DOMAIN";
        else if (rType == "HOST-SUFFIX") rType = "DOMAIN-SUFFIX";
        else if (rType == "HOST-KEYWORD") rType = "DOMAIN-KEYWORD";
        else if (rType == "HOST-WILDCARD") rType = "DOMAIN-WILDCARD";
        else if (rType == "IP6-CIDR") rType = "IP-CIDR6";
        else if (rType == "DEST-PORT") rType = "DST-PORT";
        else if (rType == "SRC-IP" || rType == "SOURCE-IP-CIDR") rType = "SRC-IP-CIDR";

        const std::string pat = unquoteCopy(cols[1]);
        bool noRes = false;
        for (size_t i = 2; i < cols.size(); ++i) {
            if (lowerAscii(cols[i]) == "no-resolve") noRes = true;
        }
        ExtraRuleKind ek = ExtraRuleKind::Compiled;
        if (rType == "PROCESS-NAME" || rType == "PROCESS-PATH") ek = ExtraRuleKind::ProcessName;
        else if (rType == "DOMAIN-WILDCARD" || rType == "DOMAIN-REGEX") ek = ExtraRuleKind::DomainWildcard;
        else if (rType == "PROTOCOL" || rType == "NETWORK") ek = ExtraRuleKind::ProtocolName;
        outRules.push_back(ParsedRule{ek, rType, pat, policy, noRes});
    }
}

std::string lookupRuleSetBehavior(const EngineProfile &profile, const std::string &keyOrUrl) {
    for (const auto &rs : profile.ruleSets) {
        if (rs.key == keyOrUrl || rs.url == keyOrUrl) return rs.behavior;
    }
    return "classical";
}

void compileRulesIntoEngineProfile(EngineProfile &profile) {
    profile.rules.clear();
    profile.rules.reserve(profile.baseRules.size() + 128);

    for (const auto &br : profile.baseRules) {
        if (br.rawType == "RULE-SET" || br.rawType == "DOMAIN-SET" || br.rawType == "GEOSITE") {
            std::string lookupKey = (br.rawType == "GEOSITE")
                ? ("GEOSITE:" + upperAscii(br.pattern))
                : br.pattern;
            std::string beh = (br.rawType == "DOMAIN-SET" || br.rawType == "GEOSITE")
                ? "domain"
                : lookupRuleSetBehavior(profile, lookupKey);
            auto it = profile.ruleSetContents.find(lookupKey);
            if (it == profile.ruleSetContents.end() && lookupKey != br.pattern) {
                it = profile.ruleSetContents.find(br.pattern);
            }
            if (it == profile.ruleSetContents.end()) {
                for (const auto &rs : profile.ruleSets) {
                    if (rs.key == lookupKey && !rs.url.empty()) {
                        it = profile.ruleSetContents.find(rs.url);
                        if (it != profile.ruleSetContents.end()) break;
                    }
                }
            }
            if (it != profile.ruleSetContents.end()) {
                parseRuleSetLinesInto(it->second, br.policy, beh, profile.rules);
            }
            continue;
        }
        if (br.rawType == "GEOIP") {
            const std::string geoCode = upperAscii(br.pattern);
            if (geoCode == "LAN" || geoCode == "PRIVATE") {
                static const char *kLanCidrs[] = {
                    "127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12",
                    "192.168.0.0/16", "100.64.0.0/10", "169.254.0.0/16"
                };
                for (const char *cidr : kLanCidrs) {
                    profile.rules.push_back(ParsedRule{ExtraRuleKind::Compiled, "IP-CIDR", cidr, br.policy, true});
                }
                profile.rules.push_back(ParsedRule{ExtraRuleKind::Compiled, "IP-CIDR6", "::1/128", br.policy, true});
                profile.rules.push_back(ParsedRule{ExtraRuleKind::Compiled, "IP-CIDR6", "fc00::/7", br.policy, true});
                profile.rules.push_back(ParsedRule{ExtraRuleKind::Compiled, "IP-CIDR6", "fe80::/10", br.policy, true});
                continue;
            }
            auto git = profile.ruleSetContents.find("GEOIP:" + geoCode);
            if (git != profile.ruleSetContents.end()) {
                parseRuleSetLinesInto(git->second, br.policy, "ipcidr", profile.rules);
            }
            continue;
        }
        profile.rules.push_back(br);
    }

    HJCompiledRules *raw = hajimi_rules_create();
    profile.compiledOrdinalPolicies.clear();
    profile.compiledOrdinalPolicies.reserve(profile.rules.size());

    for (size_t i = 0; i < profile.rules.size(); ++i) {
        const auto &r = profile.rules[i];
        const auto ord = static_cast<int32_t>(i);
        profile.compiledOrdinalPolicies.push_back(r.policy);
        if (r.extraKind != ExtraRuleKind::Compiled) continue;

        const auto *txt = reinterpret_cast<const uint8_t *>(r.pattern.data());
        const size_t txtLen = r.pattern.size();
        int32_t nodeId = -1;

        if (r.rawType == "DOMAIN" || r.rawType == "HOST") {
            nodeId = hajimi_rules_add_node(raw, HJ_RULE_DOMAIN, txt, txtLen, nullptr, 0, 0, 0);
        } else if (r.rawType == "DOMAIN-SUFFIX" || r.rawType == "HOST-SUFFIX") {
            nodeId = hajimi_rules_add_node(raw, HJ_RULE_SUFFIX, txt, txtLen, nullptr, 0, 0, 0);
        } else if (r.rawType == "DOMAIN-KEYWORD" || r.rawType == "HOST-KEYWORD") {
            nodeId = hajimi_rules_add_node(raw, HJ_RULE_KEYWORD, txt, txtLen, nullptr, 0, 0, 0);
        } else if (r.rawType == "IP-CIDR" || r.rawType == "IP-CIDR6" || r.rawType == "IP6-CIDR") {
            nodeId = hajimi_rules_add_node(raw, HJ_RULE_IP_CIDR, txt, txtLen, nullptr, 0, 0, 0);
        } else if (r.rawType == "SRC-IP-CIDR" || r.rawType == "SRC-IP") {
            nodeId = hajimi_rules_add_node(raw, HJ_RULE_SOURCE_CIDR, txt, txtLen, nullptr, 0, 0, 0);
        } else if (r.rawType == "DST-PORT" || r.rawType == "DEST-PORT") {
            uint16_t lo = 0, hi = 0;
            if (parsePortRangeString(r.pattern, lo, hi)) {
                nodeId = hajimi_rules_add_node(raw, HJ_RULE_DESTINATION_PORT, nullptr, 0, nullptr, 0, lo, hi);
            }
        } else if (r.rawType == "SRC-PORT" || r.rawType == "SOURCE-PORT") {
            uint16_t lo = 0, hi = 0;
            if (parsePortRangeString(r.pattern, lo, hi)) {
                nodeId = hajimi_rules_add_node(raw, HJ_RULE_SOURCE_PORT, nullptr, 0, nullptr, 0, lo, hi);
            }
        } else if (r.rawType == "IN-PORT") {
            uint16_t lo = 0, hi = 0;
            if (parsePortRangeString(r.pattern, lo, hi)) {
                nodeId = hajimi_rules_add_node(raw, HJ_RULE_INBOUND_PORT, nullptr, 0, nullptr, 0, lo, hi);
            }
        }
        if (nodeId >= 0) {
            (void)hajimi_rules_add_root(raw, nodeId, ord);
        }
    }
    (void)hajimi_rules_finalize(raw);
    profile.compiledRules = std::shared_ptr<HJCompiledRules>(raw, [](HJCompiledRules *p) {
        if (p) hajimi_rules_destroy(p);
    });
}

void parseRuleEntry(const std::string &line, EngineProfile &profile) {
    // Handle Surge compound logical rules `AND,((DOMAIN-KEYWORD,google),(DST-PORT,443)),Proxy`
    std::string trimmed = trimCopy(line);
    if (trimmed.empty()) return;

    auto cols = splitCsvRespectingQuotes(trimmed);
    if (cols.size() < 2) return;
    std::string rType = upperAscii(cols[0]);
    if (rType == "FINAL" || rType == "MATCH") {
        profile.finalPolicy = unquoteCopy(cols[1]);
        return;
    }

    if (rType == "AND" || rType == "OR" || rType == "NOT") {
        if (cols.size() >= 3) {
            std::string expr = cols[1];
            std::string pol = unquoteCopy(cols[2]);
            // Extract inner primary domain/process clause if single-clause wrapper, and always record in baseRules
            profile.baseRules.push_back(ParsedRule{ExtraRuleKind::Compiled, rType, expr, pol, false});
            // Also extract inner leaf `((TYPE,VALUE))` when simple so fast-path matcher catches single-clause wrappers
            std::string inner = trimCopy(expr);
            while (inner.size() >= 2 && inner.front() == '(' && inner.back() == ')') {
                inner = trimCopy(inner.substr(1, inner.size() - 2));
            }
            if (rType != "NOT" && inner.find('(') == std::string::npos) {
                auto subCols = splitCsvRespectingQuotes(inner);
                if (subCols.size() == 2) {
                    parseRuleEntry(subCols[0] + "," + subCols[1] + "," + pol, profile);
                }
            }
        }
        return;
    }

    if (cols.size() < 3) return;
    if (rType == "HOST") rType = "DOMAIN";
    else if (rType == "HOST-SUFFIX") rType = "DOMAIN-SUFFIX";
    else if (rType == "HOST-KEYWORD") rType = "DOMAIN-KEYWORD";
    else if (rType == "HOST-WILDCARD") rType = "DOMAIN-WILDCARD";
    else if (rType == "IP6-CIDR") rType = "IP-CIDR6";
    else if (rType == "DEST-PORT") rType = "DST-PORT";
    else if (rType == "SRC-IP" || rType == "SOURCE-IP-CIDR") rType = "SRC-IP-CIDR";

    std::string pat = unquoteCopy(cols[1]);
    std::string pol = unquoteCopy(cols[2]);
    bool noRes = false;
    for (size_t i = 3; i < cols.size(); ++i) {
        if (lowerAscii(cols[i]) == "no-resolve") noRes = true;
    }

    ExtraRuleKind ek = ExtraRuleKind::Compiled;
    if (rType == "PROCESS-NAME" || rType == "PROCESS-PATH") ek = ExtraRuleKind::ProcessName;
    else if (rType == "DOMAIN-WILDCARD" || rType == "DOMAIN-REGEX") ek = ExtraRuleKind::DomainWildcard;
    else if (rType == "PROTOCOL" || rType == "NETWORK") ek = ExtraRuleKind::ProtocolName;

    profile.baseRules.push_back(ParsedRule{ek, rType, pat, pol, noRes});
}

void registerRuleSetRefsFromBaseRules(
    EngineProfile &profile,
    const std::unordered_map<std::string, RuleSetReference> &providerMeta = {}) {
    auto addUniqueRef = [&](const std::string &key, const std::string &url, const std::string &pol,
                            const std::string &beh, const std::string &fmt) {
        for (auto &existing : profile.ruleSets) {
            if (existing.key == key) {
                if (existing.url.empty() && !url.empty()) existing.url = url;
                if (existing.behavior == "classical" && beh != "classical") existing.behavior = beh;
                if (existing.format == "text" && fmt != "text") existing.format = fmt;
                return;
            }
        }
        profile.ruleSets.push_back(RuleSetReference{key, url, pol, beh, fmt});
    };

    for (const auto &br : profile.baseRules) {
        if (br.rawType == "RULE-SET" || br.rawType == "DOMAIN-SET") {
            const std::string upperPat = upperAscii(br.pattern);
            if (upperPat == "LAN") {
                profile.ruleSetContents[br.pattern] = kBuiltinLanRuleset;
                continue;
            }
            if (upperPat == "SYSTEM") {
                profile.ruleSetContents[br.pattern] = kBuiltinSystemRuleset;
                continue;
            }
            std::string url;
            std::string beh = (br.rawType == "DOMAIN-SET") ? "domain" : "classical";
            std::string fmt = "text";
            auto pit = providerMeta.find(br.pattern);
            if (pit != providerMeta.end()) {
                url = pit->second.url;
                if (!pit->second.behavior.empty()) beh = pit->second.behavior;
                if (!pit->second.format.empty()) fmt = pit->second.format;
            } else if (br.pattern.find("://") != std::string::npos) {
                url = br.pattern;
                if (lowerAscii(url).find(".yaml") != std::string::npos ||
                    lowerAscii(url).find(".yml") != std::string::npos) {
                    fmt = "yaml";
                } else if (lowerAscii(url).find(".mrs") != std::string::npos) {
                    fmt = "mrs";
                }
            }
            addUniqueRef(br.pattern, url, br.policy, beh, fmt);
        } else if (br.rawType == "GEOSITE") {
            std::string code = lowerAscii(br.pattern);
            std::string key = "GEOSITE:" + upperAscii(br.pattern);
            std::string url = "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@meta/geo/geosite/" + code + ".list";
            addUniqueRef(key, url, br.policy, "domain", "text");
        } else if (br.rawType == "GEOIP") {
            std::string code = upperAscii(br.pattern);
            if (code != "LAN" && code != "PRIVATE" && !code.empty()) {
                std::string key = "GEOIP:" + code;
                std::string url = (code == "CN")
                    ? "https://testingcf.jsdelivr.net/gh/Loyalsoldier/geoip@release/text/cn.txt"
                    : ("https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@meta/geo/geoip/" + lowerAscii(code) + ".list");
                addUniqueRef(key, url, br.policy, "ipcidr", "text");
            }
        }
    }
}

void registerNodeProviderRef(EngineProfile &profile, const std::string &key, const std::string &url, uint32_t intervalSec = 3600) {
    if (key.empty() || url.empty()) return;
    for (auto &np : profile.nodeProviders) {
        if (np.key == key) {
            if (np.url.empty()) np.url = url;
            return;
        }
    }
    profile.nodeProviders.push_back(NodeProviderReference{key, url, intervalSec});
}

// ============================================================================
// Surge `.conf` Parser
// ============================================================================
bool parseSurgeConf(const std::string &text, EngineProfile &out, std::string &outError) {
    out = EngineProfile{};
    outError.clear();
    std::istringstream iss(text);
    std::string rawLine;
    std::string currentSection;
    bool sawExplicitEncryptedDns = false;
    std::unordered_map<std::string, std::unordered_map<std::string, std::string>> wgSections;

    while (std::getline(iss, rawLine)) {
        if (!rawLine.empty() && rawLine.back() == '\r') rawLine.pop_back();
        if (rawLine.size() >= 3 &&
            static_cast<unsigned char>(rawLine[0]) == 0xEF &&
            static_cast<unsigned char>(rawLine[1]) == 0xBB &&
            static_cast<unsigned char>(rawLine[2]) == 0xBF) {
            rawLine.erase(0, 3);
        }
        std::string line = trimCopy(rawLine);
        if (line.empty() || line[0] == '#' || line[0] == ';') continue;
        if (line.size() >= 2 && line[0] == '/' && line[1] == '/') continue;

        if (line.front() == '[' && line.back() == ']' && line.find('=') == std::string::npos) {
            std::string secBody = trimCopy(line.substr(1, line.size() - 2));
            std::string secLow = lowerAscii(secBody);
            if (secLow.rfind("wireguard ", 0) == 0) {
                currentSection = "wireguard:" + trimCopy(secBody.substr(10));
            } else {
                currentSection = secLow;
            }
            continue;
        }

        line = trimCopy(stripInlineLineComment(line, true));
        if (line.empty()) continue;

        if (currentSection == "general") {
            auto eq = line.find('=');
            if (eq == std::string::npos) continue;
            std::string k = lowerAscii(trimCopy(line.substr(0, eq)));
            std::string v = trimCopy(line.substr(eq + 1));
            if (k == "http-listen") {
                std::string h;
                uint16_t p = 0;
                if (splitHostPort(v, h, p)) out.httpPort = p;
            } else if (k == "wifi-access-http-port" || k == "http-port") {
                uint16_t p = extractFirstPortFromRange(v);
                if (p != 0 && out.httpPort == 0) out.httpPort = p;
            } else if (k == "socks5-listen") {
                std::string h;
                uint16_t p = 0;
                if (splitHostPort(v, h, p)) out.socksPort = p;
            } else if (k == "wifi-access-socks5-port" || k == "socks-port") {
                uint16_t p = extractFirstPortFromRange(v);
                if (p != 0 && out.socksPort == 0) out.socksPort = p;
            } else if (k == "external-controller-access") {
                auto at = v.find('@');
                if (at != std::string::npos) {
                    out.externalControllerKey = trimCopy(v.substr(0, at));
                    std::string h;
                    uint16_t p = 0;
                    if (splitHostPort(v.substr(at + 1), h, p)) out.externalControllerPort = p;
                }
            } else if (k == "http-api") {
                auto at = v.find('@');
                if (at != std::string::npos) {
                    out.externalControllerKey = trimCopy(v.substr(0, at));
                    std::string h;
                    uint16_t p = 0;
                    if (splitHostPort(v.substr(at + 1), h, p)) out.externalControllerPort = p;
                }
            } else if (k == "external-controller") {
                std::string h;
                uint16_t p = 0;
                if (splitHostPort(v, h, p)) out.externalControllerPort = p;
            } else if (k == "secret") {
                out.externalControllerKey = unquoteCopy(v);
            } else if (k == "dns-server") {
                out.dns.nameservers.clear();
                for (auto &ns : splitCsvRespectingQuotes(v)) {
                    std::string u = unquoteCopy(ns);
                    if (!u.empty() && lowerAscii(u) != "system") out.dns.nameservers.push_back(u);
                }
                if (out.dns.nameservers.empty()) out.dns.nameservers = {"1.1.1.1", "8.8.8.8"};
                if (!sawExplicitEncryptedDns) {
                    out.dns.encryptedUpstreams.clear();
                }
            } else if (k == "encrypted-dns-server" || k == "doh-server") {
                sawExplicitEncryptedDns = true;
                out.dns.encryptedUpstreams.clear();
                for (auto &ns : splitCsvRespectingQuotes(v)) {
                    if (!ns.empty()) out.dns.encryptedUpstreams.push_back(unquoteCopy(ns));
                }
            } else if (k == "ipv6") {
                out.dns.ipv6Enabled = isTruthyValue(v);
            } else if (k == "hijack-dns" || k == "enhanced-mode") {
                if (lowerAscii(v).find("fake-ip") != std::string::npos || !v.empty()) {
                    out.dns.fakeIpEnabled = true;
                }
            } else if (k == "skip-proxy") {
                out.skipProxyDomains = splitCsvRespectingQuotes(v);
            } else if (k == "tun-excluded-routes") {
                out.tun.excludedRoutes = splitCsvRespectingQuotes(v);
            } else if (k == "tun-included-routes") {
                out.tun.includedRoutes = splitCsvRespectingQuotes(v);
            }
        } else if (currentSection == "host") {
            auto eq = line.find('=');
            if (eq != std::string::npos) {
                std::string dom = lowerAscii(trimCopy(line.substr(0, eq)));
                std::string val = trimCopy(line.substr(eq + 1));
                if (!dom.empty() && !val.empty() && val.find(':') == std::string::npos) {
                    out.dns.staticHosts[dom] = val;
                }
            }
        } else if (currentSection.rfind("wireguard:", 0) == 0) {
            std::string wgName = currentSection.substr(10);
            auto eq = line.find('=');
            if (eq != std::string::npos && !wgName.empty()) {
                std::string wk = lowerAscii(trimCopy(line.substr(0, eq)));
                std::string wv = trimCopy(line.substr(eq + 1));
                wgSections[wgName][wk] = wv;
            }
        } else if (currentSection == "proxy") {
            auto eq = line.find('=');
            if (eq == std::string::npos) continue;
            std::string desiredName = unquoteCopy(line.substr(0, eq));
            auto fields = splitCsvRespectingQuotes(line.substr(eq + 1));
            if (fields.empty()) continue;

            bool impliesTls = false;
            std::string pType = normalizeProxyProtocolType(fields[0], impliesTls);
            if (pType == "direct" || pType == "reject" || pType == "reject-tinygif" || pType == "reject-drop") {
                Node builtin{};
                builtin.name = desiredName;
                builtin.type = (pType == "direct") ? "direct" : "reject";
                out.baseNodes[builtin.name] = builtin;
                continue;
            }

            Node node{};
            node.name = ensureUniqueNodeName(out, desiredName);
            node.type = pType;
            if (impliesTls) node.parameters["tls"] = "true";

            if (pType == "wireguard" && (fields.size() < 3 || fields[1].find('=') != std::string::npos)) {
                for (size_t i = 1; i < fields.size(); ++i) {
                    auto feq = fields[i].find('=');
                    if (feq != std::string::npos) {
                        std::string ok = lowerAscii(trimCopy(fields[i].substr(0, feq)));
                        std::string ov = unquoteCopy(fields[i].substr(feq + 1));
                        node.parameters[ok] = ov;
                    }
                }
                out.baseNodeOrder.push_back(node.name);
                out.baseNodes[node.name] = std::move(node);
                continue;
            }

            if (fields.size() < 3) continue;
            node.host = unquoteCopy(fields[1]);
            node.port = extractFirstPortFromRange(fields[2]);

            // Handle Surge positional parameters before `key=value` options
            size_t kvStart = 3;
            if ((pType == "http" || pType == "socks5") && fields.size() >= 5 &&
                fields[3].find('=') == std::string::npos && fields[4].find('=') == std::string::npos) {
                node.parameters["username"] = unquoteCopy(fields[3]);
                node.parameters["password"] = unquoteCopy(fields[4]);
                kvStart = 5;
            } else if (pType == "ss" && fields.size() >= 5 &&
                       fields[3].find('=') == std::string::npos && fields[4].find('=') == std::string::npos) {
                node.parameters["cipher"] = unquoteCopy(fields[3]);
                node.parameters["password"] = unquoteCopy(fields[4]);
                kvStart = 5;
                // Skip legacy Surge SSEncrypt.module positional URL if present
                if (fields.size() > kvStart && fields[kvStart].find('=') == std::string::npos &&
                    fields[kvStart].find("://") != std::string::npos) {
                    ++kvStart;
                }
            } else if ((pType == "vmess" || pType == "vless") && fields.size() >= 4 &&
                       fields[3].find('=') == std::string::npos) {
                node.parameters["uuid"] = unquoteCopy(fields[3]);
                kvStart = 4;
            } else if ((pType == "trojan" || pType == "hysteria2" || pType == "anytls") && fields.size() >= 4 &&
                       fields[3].find('=') == std::string::npos) {
                node.parameters["password"] = unquoteCopy(fields[3]);
                kvStart = 4;
            } else if (pType == "tuic" && fields.size() >= 4 && fields[3].find('=') == std::string::npos) {
                node.parameters["token"] = unquoteCopy(fields[3]);
                kvStart = 4;
            }

            for (size_t i = kvStart; i < fields.size(); ++i) {
                auto feq = fields[i].find('=');
                if (feq == std::string::npos) continue;
                std::string ok = lowerAscii(trimCopy(fields[i].substr(0, feq)));
                std::string ov = unquoteCopy(fields[i].substr(feq + 1));
                if (ok == "encrypt-method") ok = "cipher";
                if (ok == "username" && (pType == "vmess" || pType == "vless")) {
                    node.parameters["uuid"] = ov;
                } else if (ok == "ws" && isTruthyValue(ov)) {
                    node.parameters["ws"] = "true";
                    node.parameters["network"] = "ws";
                } else if (ok == "obfs" && (lowerAscii(ov) == "ws" || lowerAscii(ov) == "wss")) {
                    node.parameters["ws"] = "true";
                    node.parameters["network"] = "ws";
                    if (lowerAscii(ov) == "wss") node.parameters["tls"] = "true";
                } else if (ok == "obfs-uri") {
                    node.parameters["ws-path"] = ov;
                } else if (ok == "ws-headers") {
                    for (auto &hdrPart : splitCsvRespectingQuotes(ov)) {
                        for (auto &pipePart : [&]() {
                            std::vector<std::string> res;
                            size_t pos = 0;
                            while (pos <= hdrPart.size()) {
                                auto bar = hdrPart.find('|', pos);
                                if (bar == std::string::npos) {
                                    res.push_back(hdrPart.substr(pos));
                                    break;
                                }
                                res.push_back(hdrPart.substr(pos, bar - pos));
                                pos = bar + 1;
                            }
                            return res;
                        }()) {
                            auto colon = pipePart.find(':');
                            if (colon != std::string::npos &&
                                lowerAscii(trimCopy(pipePart.substr(0, colon))) == "host") {
                                node.parameters["ws-host"] = unquoteCopy(pipePart.substr(colon + 1));
                            }
                        }
                    }
                    node.parameters[ok] = ov;
                } else if (ok == "port-hopping" || ok == "ports") {
                    node.parameters["ports"] = ov;
                    if (node.port == 0) node.port = extractFirstPortFromRange(ov);
                } else {
                    node.parameters[ok] = ov;
                }
            }
            if (node.parameters.count("ws") && !node.parameters.count("ws-host") && node.parameters.count("obfs-host")) {
                node.parameters["ws-host"] = node.parameters["obfs-host"];
            }
            if (node.port == 0) continue;
            out.baseNodeOrder.push_back(node.name);
            out.baseNodes[node.name] = std::move(node);
        } else if (currentSection == "proxy group") {
            auto eq = line.find('=');
            if (eq == std::string::npos) continue;
            PolicyGroup grp{};
            grp.name = unquoteCopy(line.substr(0, eq));
            auto fields = splitCsvRespectingQuotes(line.substr(eq + 1));
            if (fields.empty()) continue;
            std::string gType = lowerAscii(fields[0]);
            std::replace(gType.begin(), gType.end(), '_', '-');
            if (gType == "url-test") grp.kind = PolicyGroupKind::UrlTest;
            else if (gType == "fallback") grp.kind = PolicyGroupKind::Fallback;
            else if (gType == "load-balance") grp.kind = PolicyGroupKind::LoadBalance;
            else if (gType == "smart") grp.kind = PolicyGroupKind::SmartUCB1;
            else grp.kind = PolicyGroupKind::Select;

            for (size_t i = 1; i < fields.size(); ++i) {
                auto feq = fields[i].find('=');
                if (feq != std::string::npos) {
                    std::string gk = lowerAscii(trimCopy(fields[i].substr(0, feq)));
                    std::string gv = unquoteCopy(fields[i].substr(feq + 1));
                    if (gk == "url" || gk == "test-url") grp.testUrl = gv;
                    else if (gk == "interval") grp.intervalSeconds = static_cast<uint32_t>(std::strtoul(gv.c_str(), nullptr, 10));
                    else if (gk == "tolerance") grp.toleranceMs = static_cast<uint32_t>(std::strtoul(gv.c_str(), nullptr, 10));
                    else if (gk == "include-all-proxies" || gk == "include-all") {
                        grp.includeAllProxies = isTruthyValue(gv);
                        if (grp.includeAllProxies) grp.staticMembers.push_back("\x01ALL");
                    } else if (gk == "include-other-group") {
                        for (auto &og : splitCsvRespectingQuotes(gv)) {
                            std::string cleanOg = unquoteCopy(og);
                            if (!cleanOg.empty()) {
                                grp.includeOtherGroups.push_back(cleanOg);
                                grp.staticMembers.push_back("\x01GRP:" + cleanOg);
                            }
                        }
                    } else if (gk == "policy-path") {
                        std::string provKey = "policy-path:" + grp.name;
                        registerNodeProviderRef(out, provKey, gv);
                        grp.useProviders.push_back(provKey);
                        grp.staticMembers.push_back("\x01PROV:" + provKey);
                    } else if (gk == "policy-regex-filter" || gk == "policy-name-filter" || gk == "filter") {
                        grp.includeFilterRegex = gv;
                    } else if (gk == "policy-regex-filter-exclude" || gk == "exclude-filter") {
                        grp.excludeFilterRegex = gv;
                    } else if (gk == "exclude-type") {
                        grp.excludeTypeFilter = gv;
                    }
                    continue;
                }
                std::string m = unquoteCopy(fields[i]);
                if (!m.empty()) grp.staticMembers.push_back(m);
            }
            if (out.groups.find(grp.name) == out.groups.end()) {
                out.groupOrder.push_back(grp.name);
            }
            out.groups[grp.name] = std::move(grp);
        } else if (currentSection == "rule") {
            parseRuleEntry(line, out);
        }
    }

    // Hydrate `[Proxy]` WireGuard nodes referencing `[WireGuard <SectionName>]`
    for (auto it = out.baseNodes.begin(); it != out.baseNodes.end();) {
        Node &nd = it->second;
        if (nd.type == "wireguard" && nd.host.empty()) {
            std::string secName = nd.option("section-name");
            auto wit = wgSections.find(secName);
            if (wit != wgSections.end()) {
                const auto &wmap = wit->second;
                auto copyWgKey = [&](const char *srcKey, const char *dstKey) {
                    auto kit = wmap.find(srcKey);
                    if (kit != wmap.end() && !kit->second.empty()) {
                        nd.parameters[dstKey] = unquoteCopy(kit->second);
                    }
                };
                copyWgKey("private-key", "private-key");
                copyWgKey("self-ip", "ip");
                copyWgKey("self-ip-v6", "ipv6");
                copyWgKey("mtu", "mtu");
                copyWgKey("reserved", "reserved");
                auto peerIt = wmap.find("peer");
                if (peerIt != wmap.end()) {
                    std::string peerRaw = trimCopy(peerIt->second);
                    if (!peerRaw.empty() && peerRaw.front() == '(' && peerRaw.back() == ')') {
                        peerRaw = peerRaw.substr(1, peerRaw.size() - 2);
                    }
                    for (const auto &pf : splitCsvRespectingQuotes(peerRaw)) {
                        auto peq = pf.find('=');
                        if (peq == std::string::npos) continue;
                        std::string pk = lowerAscii(trimCopy(pf.substr(0, peq)));
                        std::string pv = unquoteCopy(pf.substr(peq + 1));
                        if (pk == "endpoint") {
                            std::string eh;
                            uint16_t ep = 0;
                            if (splitHostPort(pv, eh, ep)) {
                                nd.host = eh;
                                nd.port = ep;
                            }
                        } else if (pk == "public-key") {
                            nd.parameters["public-key"] = pv;
                        } else if (pk == "preshared-key" || pk == "pre-shared-key") {
                            nd.parameters["pre-shared-key"] = pv;
                        } else if (pk == "reserved") {
                            nd.parameters["reserved"] = pv;
                        }
                    }
                }
            }
            if (nd.host.empty() || nd.port == 0) {
                out.baseNodeOrder.erase(
                    std::remove(out.baseNodeOrder.begin(), out.baseNodeOrder.end(), nd.name),
                    out.baseNodeOrder.end());
                it = out.baseNodes.erase(it);
                continue;
            }
        }
        ++it;
    }

    out.nodes = out.baseNodes;
    out.nodeOrder = out.baseNodeOrder;
    ProfileConfigParser::recomputeDynamicGroups(out);
    registerRuleSetRefsFromBaseRules(out);
    compileRulesIntoEngineProfile(out);
    // Minimal Surge profiles (e.g. `[General]\n[Rule]\nFINAL, DIRECT` on fresh startup) are valid
    return true;
}

// ============================================================================
// Clash / Mihomo YAML Parser (with `&anchor`, `*alias`, `<<:` Merge Keys,
// Dynamic Groups, `proxy-providers`, `rule-providers`, and Multi-Line Proxies)
// ============================================================================
std::unordered_map<std::string, std::string> parseYamlInlineMap(const std::string &braceExpr) {
    std::unordered_map<std::string, std::string> out;
    std::string inner = trimCopy(braceExpr);
    if (!inner.empty() && inner.front() == '{') inner.erase(inner.begin());
    if (!inner.empty() && inner.back() == '}') inner.pop_back();

    std::vector<std::string> fields;
    std::string cur;
    bool inQ = false;
    char qCh = 0;
    int depth = 0;
    for (size_t i = 0; i < inner.size(); ++i) {
        char c = inner[i];
        if (inQ) {
            if (c == '\\' && qCh == '"' && i + 1 < inner.size()) {
                cur.push_back(c);
                cur.push_back(inner[++i]);
                continue;
            }
            if (c == qCh) inQ = false;
            cur.push_back(c);
            continue;
        }
        if (c == '"' || c == '\'') {
            inQ = true;
            qCh = c;
            cur.push_back(c);
        } else if (c == '{' || c == '[') {
            ++depth;
            cur.push_back(c);
        } else if (c == '}' || c == ']') {
            if (depth > 0) --depth;
            cur.push_back(c);
        } else if (c == ',' && depth == 0) {
            fields.push_back(trimCopy(cur));
            cur.clear();
        } else {
            cur.push_back(c);
        }
    }
    if (!trimCopy(cur).empty()) fields.push_back(trimCopy(cur));

    for (const auto &f : fields) {
        auto colon = f.find(':');
        if (colon == std::string::npos) continue;
        std::string k = lowerAscii(unquoteCopy(f.substr(0, colon)));
        std::string v = trimCopy(f.substr(colon + 1));
        out[k] = v;
    }
    return out;
}

std::vector<std::string> parseYamlInlineArray(const std::string &arrExpr) {
    std::vector<std::string> out;
    std::string inner = trimCopy(arrExpr);
    if (!inner.empty() && inner.front() == '[') inner.erase(inner.begin());
    if (!inner.empty() && inner.back() == ']') inner.pop_back();
    for (auto &item : splitCsvRespectingQuotes(inner)) {
        std::string u = unquoteCopy(item);
        if (!u.empty()) out.push_back(u);
    }
    return out;
}

bool splitYamlKeyValue(const std::string &s, std::string &keyOut, std::string &valOut) {
    bool inQ = false;
    char qCh = 0;
    for (size_t i = 0; i < s.size(); ++i) {
        char c = s[i];
        if (inQ) {
            if (c == '\\' && qCh == '"' && i + 1 < s.size()) {
                ++i;
                continue;
            }
            if (c == qCh) inQ = false;
            continue;
        }
        if (c == '"' || c == '\'') {
            inQ = true;
            qCh = c;
            continue;
        }
        if (c == ':' && (i + 1 == s.size() || s[i + 1] == ' ' || s[i + 1] == '\t')) {
            keyOut = trimCopy(s.substr(0, i));
            valOut = (i + 1 < s.size()) ? trimCopy(s.substr(i + 1)) : std::string{};
            return !keyOut.empty();
        }
    }
    return false;
}

/// Strips a leading `&anchorName` token from a YAML value, returning the anchor name if present.
std::string extractLeadingYamlAnchor(std::string &valInOut) {
    std::string t = trimCopy(valInOut);
    if (t.size() < 2 || t[0] != '&') return {};
    size_t i = 1;
    while (i < t.size() && t[i] != ' ' && t[i] != '\t' && t[i] != '{' && t[i] != '[') ++i;
    std::string anchor = t.substr(1, i - 1);
    valInOut = trimCopy(t.substr(i));
    return anchor;
}

void applyClashFieldToNode(Node &n, const std::string &rawKey, const std::string &rawVal) {
    const std::string k = lowerAscii(trimCopy(rawKey));
    const std::string v = unquoteCopy(rawVal);
    if (k.empty()) return;

    if (k == "name") {
        n.name = v;
    } else if (k == "type") {
        bool impliesTls = false;
        n.type = normalizeProxyProtocolType(v, impliesTls);
        if (impliesTls) n.parameters["tls"] = "true";
    } else if (k == "server") {
        n.host = v;
    } else if (k == "port") {
        uint16_t p = extractFirstPortFromRange(v);
        if (p != 0) n.port = p;
    } else if (k == "ports" || k == "port-range") {
        n.parameters["ports"] = v;
        n.parameters["port-range"] = v;
        if (n.port == 0) n.port = extractFirstPortFromRange(v);
    } else if (k == "ws-opts" && !rawVal.empty() && rawVal.front() == '{') {
        auto wm = parseYamlInlineMap(rawVal);
        if (wm.count("path")) n.parameters["ws-path"] = unquoteCopy(wm["path"]);
        if (wm.count("headers")) {
            auto hm = parseYamlInlineMap(wm["headers"]);
            if (hm.count("host")) n.parameters["ws-host"] = unquoteCopy(hm["host"]);
        }
    } else if (k == "grpc-opts" && !rawVal.empty() && rawVal.front() == '{') {
        auto gm = parseYamlInlineMap(rawVal);
        if (gm.count("grpc-service-name")) n.parameters["grpc-service-name"] = unquoteCopy(gm["grpc-service-name"]);
        else if (gm.count("servicename")) n.parameters["grpc-service-name"] = unquoteCopy(gm["servicename"]);
    } else if ((k == "xhttp-opts" || k == "splithttp-opts") && !rawVal.empty() && rawVal.front() == '{') {
        auto xm = parseYamlInlineMap(rawVal);
        if (xm.count("path")) n.parameters["xhttp-path"] = unquoteCopy(xm["path"]);
        if (xm.count("host")) n.parameters["xhttp-host"] = unquoteCopy(xm["host"]);
        if (xm.count("mode")) n.parameters["xhttp-mode"] = unquoteCopy(xm["mode"]);
        if (xm.count("x-padding-bytes")) n.parameters["xhttp-padding-bytes"] = unquoteCopy(xm["x-padding-bytes"]);
    } else if (k == "reality-opts" && !rawVal.empty() && rawVal.front() == '{') {
        auto rm = parseYamlInlineMap(rawVal);
        if (rm.count("public-key")) {
            n.parameters["security"] = "reality";
            n.parameters["tls"] = "true";
            n.parameters["reality-public-key"] = unquoteCopy(rm["public-key"]);
        }
        if (rm.count("short-id")) n.parameters["reality-short-id"] = unquoteCopy(rm["short-id"]);
    } else if (k == "plugin-opts" && !rawVal.empty() && rawVal.front() == '{') {
        auto pm = parseYamlInlineMap(rawVal);
        std::string plug = lowerAscii(n.option("plugin"));
        if (plug == "obfs" || plug == "obfs-local" || plug == "simple-obfs") {
            if (pm.count("mode")) n.parameters["obfs"] = unquoteCopy(pm["mode"]);
            if (pm.count("host")) n.parameters["obfs-host"] = unquoteCopy(pm["host"]);
        } else if (plug == "v2ray-plugin") {
            if (!pm.count("mode") || lowerAscii(unquoteCopy(pm["mode"])) == "websocket") {
                n.parameters["ws"] = "true";
                n.parameters["network"] = "ws";
            }
            if (pm.count("tls") && isTruthyValue(pm["tls"])) n.parameters["tls"] = "true";
            if (pm.count("path")) n.parameters["ws-path"] = unquoteCopy(pm["path"]);
            if (pm.count("host")) n.parameters["ws-host"] = unquoteCopy(pm["host"]);
            if (pm.count("skip-cert-verify")) n.parameters["skip-cert-verify"] = unquoteCopy(pm["skip-cert-verify"]);
        } else if (plug == "shadow-tls") {
            if (pm.count("host")) n.parameters["shadow-tls-sni"] = unquoteCopy(pm["host"]);
            if (pm.count("password")) n.parameters["shadow-tls-password"] = unquoteCopy(pm["password"]);
            if (pm.count("version")) n.parameters["shadow-tls-version"] = unquoteCopy(pm["version"]);
        }
    } else if (k == "peers" && !rawVal.empty() && rawVal.front() == '[') {
        // Inline `peers: [{ server: ..., port: ..., public-key: ... }]`
        std::string inner = trimCopy(rawVal.substr(1, rawVal.size() - 2));
        if (!inner.empty() && inner.front() == '{') {
            auto peerMap = parseYamlInlineMap(inner);
            if (peerMap.count("server") && n.host.empty()) n.host = unquoteCopy(peerMap["server"]);
            if (peerMap.count("port") && n.port == 0) n.port = extractFirstPortFromRange(peerMap["port"]);
            if (peerMap.count("public-key")) n.parameters["public-key"] = unquoteCopy(peerMap["public-key"]);
            if (peerMap.count("pre-shared-key")) n.parameters["pre-shared-key"] = unquoteCopy(peerMap["pre-shared-key"]);
            if (peerMap.count("reserved")) {
                auto rv = parseYamlInlineArray(peerMap["reserved"]);
                std::string joined;
                for (size_t ri = 0; ri < rv.size(); ++ri) {
                    if (ri > 0) joined += ",";
                    joined += rv[ri];
                }
                if (!joined.empty()) n.parameters["reserved"] = joined;
            }
        }
    } else if (k == "alpn" && !rawVal.empty() && rawVal.front() == '[') {
        auto arr = parseYamlInlineArray(rawVal);
        std::string joined;
        for (size_t i = 0; i < arr.size(); ++i) {
            if (i > 0) joined += ",";
            joined += arr[i];
        }
        if (!joined.empty()) n.parameters["alpn"] = joined;
    } else if (k == "reserved" && !rawVal.empty() && rawVal.front() == '[') {
        auto arr = parseYamlInlineArray(rawVal);
        std::string joined;
        for (size_t i = 0; i < arr.size(); ++i) {
            if (i > 0) joined += ",";
            joined += arr[i];
        }
        if (!joined.empty()) n.parameters["reserved"] = joined;
    } else if (k == "servername") {
        n.parameters["sni"] = v;
        n.parameters["servername"] = v;
    } else if (k == "client-fingerprint") {
        n.parameters["client-fingerprint"] = v;
        n.parameters["fingerprint"] = v;
    } else if (k == "dialer-proxy" || k == "underlying-proxy") {
        n.parameters["underlying-proxy"] = v;
        n.parameters["dialer-proxy"] = v;
    } else if (k == "alterid") {
        n.parameters["alter-id"] = v;
    } else if (k == "fast-open") {
        n.parameters["tfo"] = v;
    } else if (k == "auth_str" || k == "auth-string") {
        n.parameters["auth-str"] = v;
    } else if (k == "preshared-key") {
        n.parameters["pre-shared-key"] = v;
    } else if (k == "network") {
        std::string lowNet = lowerAscii(v);
        n.parameters["network"] = lowNet;
        if (lowNet == "ws") n.parameters["ws"] = "true";
    } else {
        n.parameters[k] = v;
    }
}

void finalizeClashNodeDefaults(Node &n) {
    if ((n.type == "trojan" || n.type == "hysteria2" || n.type == "hysteria" ||
         n.type == "tuic" || n.type == "anytls") &&
        n.parameters.find("tls") == n.parameters.end()) {
        n.parameters["tls"] = "true";
    }
    if (n.type == "wireguard" && n.parameters.find("udp") == n.parameters.end()) {
        n.parameters["udp"] = "true";
    }
}

bool parseClashYaml(const std::string &text, EngineProfile &out, std::string &outError) {
    out = EngineProfile{};

    // First-pass tokenization + YAML `&anchor` capture (both flow `{...}` and block mappings)
    struct YamlLine {
        size_t indent = 0;
        std::string trimmed;
    };
    std::vector<YamlLine> lines;
    {
        std::istringstream iss(text);
        std::string raw;
        while (std::getline(iss, raw)) {
            if (!raw.empty() && raw.back() == '\r') raw.pop_back();
            if (raw.size() >= 3 &&
                static_cast<unsigned char>(raw[0]) == 0xEF &&
                static_cast<unsigned char>(raw[1]) == 0xBB &&
                static_cast<unsigned char>(raw[2]) == 0xBF) {
                raw.erase(0, 3);
            }
            std::string uncommented = stripInlineLineComment(raw, false);
            size_t indent = 0;
            while (indent < uncommented.size() && (uncommented[indent] == ' ' || uncommented[indent] == '\t')) {
                indent += (uncommented[indent] == '\t') ? 2 : 1;
            }
            std::string trimmed = trimCopy(uncommented);
            if (trimmed.empty() || trimmed == "---" || trimmed == "...") continue;
            lines.push_back(YamlLine{indent, std::move(trimmed)});
        }
    }

    // Collect YAML anchors (`&anchorName`) -> key/value map so `<<: *anchorName` & `*alias` work everywhere
    std::unordered_map<std::string, std::unordered_map<std::string, std::string>> yamlAnchors;
    for (size_t idx = 0; idx < lines.size(); ++idx) {
        std::string work = lines[idx].trimmed;
        size_t anchorScopeIndent = lines[idx].indent;
        if (work[0] == '-' && (work.size() == 1 || work[1] == ' ' || work[1] == '\t')) {
            work = trimCopy(work.substr(1));
            anchorScopeIndent += 2;
        }
        std::string anchorName;
        if (!work.empty() && work[0] == '&') {
            anchorName = extractLeadingYamlAnchor(work);
        } else {
            std::string k, v;
            if (splitYamlKeyValue(work, k, v) && !v.empty() && v[0] == '&') {
                anchorName = extractLeadingYamlAnchor(v);
                work = v;
            }
        }
        if (anchorName.empty()) continue;

        auto &amap = yamlAnchors[anchorName];
        if (!work.empty() && work.front() == '{') {
            auto inlineMap = parseYamlInlineMap(work);
            for (const auto &kv : inlineMap) amap[kv.first] = kv.second;
        } else {
            // Collect indented block mapping lines belonging to this anchor
            for (size_t j = idx + 1; j < lines.size(); ++j) {
                if (lines[j].indent <= lines[idx].indent) break;
                if (lines[j].trimmed[0] == '-') continue;
                std::string ck, cv;
                if (splitYamlKeyValue(lines[j].trimmed, ck, cv) && !cv.empty() && cv.front() != '&') {
                    std::string lowCk = lowerAscii(unquoteCopy(ck));
                    if (lowCk == "<<") {
                        for (const auto &aliasTok : parseYamlInlineArray(cv)) {
                            if (!aliasTok.empty() && aliasTok[0] == '*') {
                                auto ait = yamlAnchors.find(aliasTok.substr(1));
                                if (ait != yamlAnchors.end()) {
                                    for (const auto &akv : ait->second) {
                                        if (!amap.count(akv.first)) amap[akv.first] = akv.second;
                                    }
                                }
                            }
                        }
                    } else {
                        amap[lowCk] = cv;
                    }
                }
            }
        }
        (void)anchorScopeIndent;
    }

    auto expandMergeAndAliasesInMap = [&](std::unordered_map<std::string, std::string> &m) {
        auto mit = m.find("<<");
        if (mit != m.end()) {
            std::string rawMerge = mit->second;
            m.erase(mit);
            for (const auto &tok : parseYamlInlineArray(rawMerge)) {
                std::string cleanTok = trimCopy(tok);
                if (!cleanTok.empty() && cleanTok[0] == '*') {
                    auto ait = yamlAnchors.find(cleanTok.substr(1));
                    if (ait != yamlAnchors.end()) {
                        for (const auto &akv : ait->second) {
                            if (m.find(akv.first) == m.end()) m[akv.first] = akv.second;
                        }
                    }
                }
            }
        }
        for (auto &kv : m) {
            std::string t = trimCopy(kv.second);
            if (t.size() > 1 && t[0] == '*') {
                auto ait = yamlAnchors.find(t.substr(1));
                if (ait != yamlAnchors.end() && ait->second.size() == 1) {
                    kv.second = ait->second.begin()->second;
                }
            }
        }
    };

    std::string section;
    std::string dnsSubList;
    Node pendingProxy{};
    bool hasPendingProxy = false;
    size_t proxyItemIndent = 0;
    std::string proxyNestedBlock;
    size_t proxyNestedIndent = 0;
    bool inWsHeadersBlock = false;
    size_t wsHeadersIndent = 0;
    bool inWgPeersBlock = false;
    size_t wgPeersIndent = 0;

    PolicyGroup pendingGroup{};
    bool hasPendingGroup = false;
    size_t groupItemIndent = 0;
    std::string groupSubList; // "proxies" | "use" | "include-other-group"
    size_t groupSubListIndent = 0;

    std::unordered_map<std::string, RuleSetReference> ruleProviders;
    std::string currentRuleProviderName;
    size_t ruleProviderIndent = 0;

    std::string currentProxyProviderName;
    std::string currentProxyProviderUrl;
    uint32_t currentProxyProviderInterval = 3600;
    size_t proxyProviderIndent = 0;

    auto flushProxyProvider = [&]() {
        if (!currentProxyProviderName.empty() && !currentProxyProviderUrl.empty()) {
            registerNodeProviderRef(out, currentProxyProviderName, currentProxyProviderUrl, currentProxyProviderInterval);
        }
        currentProxyProviderName.clear();
        currentProxyProviderUrl.clear();
        currentProxyProviderInterval = 3600;
    };

    auto flushProxy = [&]() {
        if (!hasPendingProxy) return;
        finalizeClashNodeDefaults(pendingProxy);
        if (!pendingProxy.name.empty() && !pendingProxy.type.empty() &&
            !pendingProxy.host.empty() && pendingProxy.port != 0) {
            pendingProxy.name = ensureUniqueNodeName(out, pendingProxy.name);
            out.baseNodeOrder.push_back(pendingProxy.name);
            out.baseNodes[pendingProxy.name] = pendingProxy;
        }
        pendingProxy = Node{};
        hasPendingProxy = false;
        proxyNestedBlock.clear();
        inWsHeadersBlock = false;
        inWgPeersBlock = false;
    };

    auto flushGroup = [&]() {
        if (!hasPendingGroup) return;
        if (!pendingGroup.name.empty()) {
            if (out.groups.find(pendingGroup.name) == out.groups.end()) {
                out.groupOrder.push_back(pendingGroup.name);
            }
            out.groups[pendingGroup.name] = pendingGroup;
        }
        pendingGroup = PolicyGroup{};
        hasPendingGroup = false;
        groupSubList.clear();
    };

    auto applyGroupKeyValue = [&](PolicyGroup &g, const std::string &rawK, const std::string &rawV) {
        const std::string gk = lowerAscii(unquoteCopy(rawK));
        if (gk == "<<") {
            for (const auto &tok : parseYamlInlineArray(rawV)) {
                if (!tok.empty() && tok[0] == '*') {
                    auto ait = yamlAnchors.find(tok.substr(1));
                    if (ait != yamlAnchors.end()) {
                        for (const auto &akv : ait->second) {
                            if (akv.first == "type" && g.kind == PolicyGroupKind::Select) {
                                std::string gt = lowerAscii(unquoteCopy(akv.second));
                                if (gt == "url-test") g.kind = PolicyGroupKind::UrlTest;
                                else if (gt == "fallback") g.kind = PolicyGroupKind::Fallback;
                                else if (gt == "load-balance") g.kind = PolicyGroupKind::LoadBalance;
                                else if (gt == "smart") g.kind = PolicyGroupKind::SmartUCB1;
                            } else if (akv.first == "url" || akv.first == "test-url") {
                                g.testUrl = unquoteCopy(akv.second);
                            } else if (akv.first == "interval") {
                                g.intervalSeconds = static_cast<uint32_t>(std::strtoul(akv.second.c_str(), nullptr, 10));
                            } else if (akv.first == "tolerance") {
                                g.toleranceMs = static_cast<uint32_t>(std::strtoul(akv.second.c_str(), nullptr, 10));
                            } else if (akv.first == "include-all" || akv.first == "include-all-proxies" || akv.first == "use-all-proxies") {
                                g.includeAllProxies = isTruthyValue(akv.second);
                            } else if (akv.first == "filter" || akv.first == "policy-regex-filter") {
                                if (g.includeFilterRegex.empty()) g.includeFilterRegex = unquoteCopy(akv.second);
                            } else if (akv.first == "exclude-filter" || akv.first == "policy-regex-filter-exclude") {
                                if (g.excludeFilterRegex.empty()) g.excludeFilterRegex = unquoteCopy(akv.second);
                            } else if (akv.first == "exclude-type") {
                                if (g.excludeTypeFilter.empty()) g.excludeTypeFilter = unquoteCopy(akv.second);
                            } else if (akv.first == "use" && !akv.second.empty() && akv.second.front() == '[') {
                                for (auto &u : parseYamlInlineArray(akv.second)) g.useProviders.push_back(u);
                            } else if (akv.first == "proxies" && !akv.second.empty() && akv.second.front() == '[') {
                                for (auto &p : parseYamlInlineArray(akv.second)) g.staticMembers.push_back(p);
                            }
                        }
                    }
                }
            }
            return;
        }
        const std::string gv = unquoteCopy(rawV);
        if (gk == "name") {
            g.name = gv;
        } else if (gk == "type") {
            std::string gt = lowerAscii(gv);
            if (gt == "url-test") g.kind = PolicyGroupKind::UrlTest;
            else if (gt == "fallback") g.kind = PolicyGroupKind::Fallback;
            else if (gt == "load-balance") g.kind = PolicyGroupKind::LoadBalance;
            else if (gt == "smart") g.kind = PolicyGroupKind::SmartUCB1;
            else g.kind = PolicyGroupKind::Select;
        } else if (gk == "proxies") {
            if (!rawV.empty() && rawV.front() == '[') {
                for (auto &m : parseYamlInlineArray(rawV)) g.staticMembers.push_back(m);
            }
        } else if (gk == "use") {
            if (!rawV.empty() && rawV.front() == '[') {
                for (auto &u : parseYamlInlineArray(rawV)) g.useProviders.push_back(u);
            }
        } else if (gk == "include-other-group") {
            if (!rawV.empty() && rawV.front() == '[') {
                for (auto &og : parseYamlInlineArray(rawV)) g.includeOtherGroups.push_back(og);
            } else if (!gv.empty()) {
                for (auto &og : splitCsvRespectingQuotes(gv)) {
                    if (!og.empty()) g.includeOtherGroups.push_back(unquoteCopy(og));
                }
            }
        } else if (gk == "include-all" || gk == "include-all-proxies" || gk == "use-all-proxies") {
            g.includeAllProxies = isTruthyValue(gv);
        } else if (gk == "filter" || gk == "policy-regex-filter" || gk == "policy-name-filter") {
            g.includeFilterRegex = gv;
        } else if (gk == "exclude-filter" || gk == "policy-regex-filter-exclude") {
            g.excludeFilterRegex = gv;
        } else if (gk == "exclude-type") {
            g.excludeTypeFilter = gv;
        } else if (gk == "url" || gk == "test-url") {
            if (!gv.empty()) g.testUrl = gv;
        } else if (gk == "interval") {
            g.intervalSeconds = static_cast<uint32_t>(std::strtoul(gv.c_str(), nullptr, 10));
        } else if (gk == "tolerance") {
            g.toleranceMs = static_cast<uint32_t>(std::strtoul(gv.c_str(), nullptr, 10));
        }
    };

    for (const auto &yl : lines) {
        const size_t indent = yl.indent;
        const std::string &trimmed = yl.trimmed;

        if (indent == 0 && trimmed[0] != '-') {
            flushProxy();
            flushGroup();
            flushProxyProvider();
            dnsSubList.clear();
            currentRuleProviderName.clear();

            std::string k, v;
            if (splitYamlKeyValue(trimmed, k, v)) {
                (void)extractLeadingYamlAnchor(v);
                std::string lk = lowerAscii(unquoteCopy(k));
                if (lk == "port" || lk == "mixed-port") {
                    uint16_t p = extractFirstPortFromRange(v);
                    if (p != 0) {
                        out.httpPort = p;
                        if (lk == "mixed-port" && out.socksPort == 0) out.socksPort = p;
                    }
                    section.clear();
                } else if (lk == "socks-port") {
                    uint16_t p = extractFirstPortFromRange(v);
                    if (p != 0) out.socksPort = p;
                    section.clear();
                } else if (lk == "ipv6") {
                    out.dns.ipv6Enabled = isTruthyValue(v);
                    section.clear();
                } else if (lk == "external-controller") {
                    std::string h;
                    uint16_t p = 0;
                    if (splitHostPort(unquoteCopy(v), h, p)) out.externalControllerPort = p;
                    section.clear();
                } else if (lk == "secret") {
                    out.externalControllerKey = unquoteCopy(v);
                    section.clear();
                } else {
                    section = lk;
                }
            }
            continue;
        }

        if (section == "dns") {
            if (trimmed[0] == '-' && !dnsSubList.empty()) {
                std::string item = unquoteCopy(trimmed.substr(1));
                if (auto hash = item.find('#'); hash != std::string::npos) {
                    item = trimCopy(item.substr(0, hash));
                }
                if (!item.empty() && lowerAscii(item) != "system") {
                    if (item.find("https://") == 0 || item.find("tls://") == 0 ||
                        item.find("quic://") == 0 || item.find("h3://") == 0) {
                        out.dns.encryptedUpstreams.push_back(item);
                    } else {
                        out.dns.nameservers.push_back(item);
                    }
                }
                continue;
            }
            std::string k, v;
            if (splitYamlKeyValue(trimmed, k, v)) {
                std::string lk = lowerAscii(unquoteCopy(k));
                if (lk == "enhanced-mode") {
                    out.dns.fakeIpEnabled = (lowerAscii(unquoteCopy(v)) == "fake-ip");
                    dnsSubList.clear();
                } else if (lk == "ipv6") {
                    out.dns.ipv6Enabled = isTruthyValue(v);
                    dnsSubList.clear();
                } else if (lk == "nameserver" || lk == "fallback" || lk == "default-nameserver") {
                    dnsSubList = lk;
                    if (lk == "nameserver") out.dns.nameservers.clear();
                    if (!v.empty() && v.front() == '[') {
                        for (const auto &ns : parseYamlInlineArray(v)) {
                            if (ns.find("https://") == 0 || ns.find("tls://") == 0) {
                                out.dns.encryptedUpstreams.push_back(ns);
                            } else {
                                out.dns.nameservers.push_back(ns);
                            }
                        }
                        dnsSubList.clear();
                    }
                } else {
                    dnsSubList.clear();
                }
            }
            continue;
        }

        if (section == "hosts") {
            std::string k, v;
            if (splitYamlKeyValue(trimmed, k, v)) {
                std::string dom = lowerAscii(unquoteCopy(k));
                std::string ip = unquoteCopy(v);
                if (!v.empty() && v.front() == '[') {
                    auto ips = parseYamlInlineArray(v);
                    if (!ips.empty()) ip = ips.front();
                }
                if (!dom.empty() && !ip.empty()) out.dns.staticHosts[dom] = ip;
            }
            continue;
        }

        if (section == "rule-providers") {
            std::string k, v;
            if (splitYamlKeyValue(trimmed, k, v)) {
                (void)extractLeadingYamlAnchor(v);
                std::string cleanKey = unquoteCopy(k);
                std::string lowKey = lowerAscii(cleanKey);

                const bool isProviderField = !currentRuleProviderName.empty() && indent > ruleProviderIndent &&
                    (lowKey == "type" || lowKey == "behavior" || lowKey == "format" || lowKey == "url" ||
                     lowKey == "path" || lowKey == "interval" || lowKey == "proxy" || lowKey == "<<");

                if (!isProviderField && (currentRuleProviderName.empty() || indent <= ruleProviderIndent)) {
                    currentRuleProviderName = cleanKey;
                    ruleProviderIndent = indent;
                    auto &rp = ruleProviders[currentRuleProviderName];
                    rp.key = currentRuleProviderName;
                    if (!v.empty() && v.front() == '{') {
                        auto pm = parseYamlInlineMap(v);
                        expandMergeAndAliasesInMap(pm);
                        if (pm.count("url")) rp.url = unquoteCopy(pm["url"]);
                        if (pm.count("behavior")) rp.behavior = lowerAscii(unquoteCopy(pm["behavior"]));
                        if (pm.count("format")) rp.format = lowerAscii(unquoteCopy(pm["format"]));
                    }
                } else if (!currentRuleProviderName.empty() && indent > ruleProviderIndent) {
                    auto &rp = ruleProviders[currentRuleProviderName];
                    rp.key = currentRuleProviderName;
                    if (lowKey == "<<") {
                        for (const auto &tok : parseYamlInlineArray(v)) {
                            if (!tok.empty() && tok[0] == '*') {
                                auto ait = yamlAnchors.find(tok.substr(1));
                                if (ait != yamlAnchors.end()) {
                                    if (ait->second.count("behavior") && rp.behavior == "classical") {
                                        rp.behavior = lowerAscii(unquoteCopy(ait->second.at("behavior")));
                                    }
                                    if (ait->second.count("format") && rp.format == "text") {
                                        rp.format = lowerAscii(unquoteCopy(ait->second.at("format")));
                                    }
                                    if (ait->second.count("url") && rp.url.empty()) {
                                        rp.url = unquoteCopy(ait->second.at("url"));
                                    }
                                }
                            }
                        }
                    } else if (lowKey == "url") {
                        rp.url = unquoteCopy(v);
                    } else if (lowKey == "behavior") {
                        rp.behavior = lowerAscii(unquoteCopy(v));
                    } else if (lowKey == "format") {
                        rp.format = lowerAscii(unquoteCopy(v));
                    }
                }
            }
            continue;
        }

        if (section == "proxy-providers") {
            std::string k, v;
            if (splitYamlKeyValue(trimmed, k, v)) {
                (void)extractLeadingYamlAnchor(v);
                std::string cleanKey = unquoteCopy(k);
                std::string lowKey = lowerAscii(cleanKey);
                const bool isField = !currentProxyProviderName.empty() && indent > proxyProviderIndent &&
                    (lowKey == "type" || lowKey == "url" || lowKey == "path" || lowKey == "interval" ||
                     lowKey == "proxy" || lowKey == "health-check" || lowKey == "override" ||
                     lowKey == "filter" || lowKey == "exclude-filter" || lowKey == "<<");

                if (!isField && (currentProxyProviderName.empty() || indent <= proxyProviderIndent)) {
                    flushProxyProvider();
                    currentProxyProviderName = cleanKey;
                    proxyProviderIndent = indent;
                    if (!v.empty() && v.front() == '{') {
                        auto pm = parseYamlInlineMap(v);
                        expandMergeAndAliasesInMap(pm);
                        if (pm.count("url")) currentProxyProviderUrl = unquoteCopy(pm["url"]);
                        if (pm.count("interval")) {
                            currentProxyProviderInterval = static_cast<uint32_t>(
                                std::strtoul(pm["interval"].c_str(), nullptr, 10));
                        }
                        flushProxyProvider();
                    }
                } else if (!currentProxyProviderName.empty() && indent > proxyProviderIndent) {
                    if (lowKey == "<<") {
                        for (const auto &tok : parseYamlInlineArray(v)) {
                            if (!tok.empty() && tok[0] == '*') {
                                auto ait = yamlAnchors.find(tok.substr(1));
                                if (ait != yamlAnchors.end()) {
                                    if (ait->second.count("url") && currentProxyProviderUrl.empty()) {
                                        currentProxyProviderUrl = unquoteCopy(ait->second.at("url"));
                                    }
                                    if (ait->second.count("interval")) {
                                        currentProxyProviderInterval = static_cast<uint32_t>(
                                            std::strtoul(ait->second.at("interval").c_str(), nullptr, 10));
                                    }
                                }
                            }
                        }
                    } else if (lowKey == "url") {
                        currentProxyProviderUrl = unquoteCopy(v);
                    } else if (lowKey == "interval") {
                        currentProxyProviderInterval = static_cast<uint32_t>(std::strtoul(v.c_str(), nullptr, 10));
                    }
                }
            }
            continue;
        }

        if (section == "proxies") {
            if (trimmed[0] == '-' && (!hasPendingProxy || indent <= proxyItemIndent)) {
                flushProxy();
                std::string rest = trimCopy(trimmed.substr(1));
                (void)extractLeadingYamlAnchor(rest);
                if (!rest.empty() && rest.front() == '{') {
                    auto m = parseYamlInlineMap(rest);
                    expandMergeAndAliasesInMap(m);
                    Node n{};
                    // Apply plugin name before plugin-opts so plugin-opts knows which plugin is active
                    if (m.count("plugin")) n.parameters["plugin"] = unquoteCopy(m["plugin"]);
                    for (const auto &kv : m) {
                        applyClashFieldToNode(n, kv.first, kv.second);
                    }
                    finalizeClashNodeDefaults(n);
                    if (!n.name.empty() && !n.type.empty() && !n.host.empty() && n.port != 0) {
                        n.name = ensureUniqueNodeName(out, n.name);
                        out.baseNodeOrder.push_back(n.name);
                        out.baseNodes[n.name] = std::move(n);
                    }
                } else {
                    hasPendingProxy = true;
                    proxyItemIndent = indent;
                    std::string k, v;
                    if (!rest.empty() && splitYamlKeyValue(rest, k, v)) {
                        (void)extractLeadingYamlAnchor(v);
                        applyClashFieldToNode(pendingProxy, k, v);
                    }
                }
                continue;
            }

            if (hasPendingProxy && indent > proxyItemIndent) {
                // Handle list items under nested proxy fields (`alpn:`, `peers:`, `reserved:`)
                if (trimmed[0] == '-') {
                    std::string item = trimCopy(trimmed.substr(1));
                    if (inWgPeersBlock) {
                        if (!item.empty() && item.front() == '{') {
                            applyClashFieldToNode(pendingProxy, "peers", "[" + item + "]");
                        } else {
                            std::string pk, pv;
                            if (splitYamlKeyValue(item, pk, pv)) {
                                std::string lowPk = lowerAscii(unquoteCopy(pk));
                                if (lowPk == "server" && pendingProxy.host.empty()) pendingProxy.host = unquoteCopy(pv);
                                else if (lowPk == "port" && pendingProxy.port == 0) pendingProxy.port = extractFirstPortFromRange(pv);
                                else if (lowPk == "public-key") pendingProxy.parameters["public-key"] = unquoteCopy(pv);
                                else if (lowPk == "pre-shared-key") pendingProxy.parameters["pre-shared-key"] = unquoteCopy(pv);
                                else if (lowPk == "reserved") applyClashFieldToNode(pendingProxy, "reserved", pv);
                            }
                        }
                    } else if (proxyNestedBlock == "alpn") {
                        std::string u = unquoteCopy(item);
                        if (!u.empty()) {
                            std::string &cur = pendingProxy.parameters["alpn"];
                            if (!cur.empty()) cur += ",";
                            cur += u;
                        }
                    } else if (proxyNestedBlock == "reserved") {
                        std::string u = unquoteCopy(item);
                        if (!u.empty()) {
                            std::string &cur = pendingProxy.parameters["reserved"];
                            if (!cur.empty()) cur += ",";
                            cur += u;
                        }
                    }
                    continue;
                }

                std::string k, v;
                if (!splitYamlKeyValue(trimmed, k, v)) continue;
                (void)extractLeadingYamlAnchor(v);
                std::string lk = lowerAscii(unquoteCopy(k));

                if (inWsHeadersBlock && indent <= wsHeadersIndent) inWsHeadersBlock = false;
                if (inWgPeersBlock && indent <= wgPeersIndent) inWgPeersBlock = false;
                if (!proxyNestedBlock.empty() && indent <= proxyNestedIndent) {
                    proxyNestedBlock.clear();
                    inWsHeadersBlock = false;
                }

                if (inWsHeadersBlock) {
                    if (lk == "host") {
                        if (proxyNestedBlock == "xhttp-opts" || proxyNestedBlock == "splithttp-opts") {
                            pendingProxy.parameters["xhttp-host"] = unquoteCopy(v);
                        } else {
                            pendingProxy.parameters["ws-host"] = unquoteCopy(v);
                        }
                    }
                    continue;
                }

                if (inWgPeersBlock && indent > wgPeersIndent) {
                    if (lk == "server" && pendingProxy.host.empty()) pendingProxy.host = unquoteCopy(v);
                    else if (lk == "port" && pendingProxy.port == 0) pendingProxy.port = extractFirstPortFromRange(v);
                    else if (lk == "public-key") pendingProxy.parameters["public-key"] = unquoteCopy(v);
                    else if (lk == "pre-shared-key") pendingProxy.parameters["pre-shared-key"] = unquoteCopy(v);
                    else if (lk == "reserved") applyClashFieldToNode(pendingProxy, "reserved", v);
                    continue;
                }

                if (!proxyNestedBlock.empty() && indent > proxyNestedIndent) {
                    if (proxyNestedBlock == "ws-opts") {
                        if (lk == "path") pendingProxy.parameters["ws-path"] = unquoteCopy(v);
                        else if (lk == "headers") {
                            if (!v.empty() && v.front() == '{') {
                                auto hm = parseYamlInlineMap(v);
                                if (hm.count("host")) pendingProxy.parameters["ws-host"] = unquoteCopy(hm["host"]);
                            } else {
                                inWsHeadersBlock = true;
                                wsHeadersIndent = indent;
                            }
                        }
                    } else if (proxyNestedBlock == "grpc-opts") {
                        if (lk == "grpc-service-name" || lk == "servicename") {
                            pendingProxy.parameters["grpc-service-name"] = unquoteCopy(v);
                        }
                    } else if (proxyNestedBlock == "xhttp-opts" || proxyNestedBlock == "splithttp-opts") {
                        if (lk == "path") pendingProxy.parameters["xhttp-path"] = unquoteCopy(v);
                        else if (lk == "host") pendingProxy.parameters["xhttp-host"] = unquoteCopy(v);
                        else if (lk == "mode") pendingProxy.parameters["xhttp-mode"] = unquoteCopy(v);
                        else if (lk == "x-padding-bytes" || lk == "xpaddingbytes") {
                            pendingProxy.parameters["xhttp-padding-bytes"] = unquoteCopy(v);
                        } else if (lk == "headers") {
                            inWsHeadersBlock = true;
                            wsHeadersIndent = indent;
                        }
                    } else if (proxyNestedBlock == "reality-opts") {
                        if (lk == "public-key" || lk == "publickey") {
                            pendingProxy.parameters["security"] = "reality";
                            pendingProxy.parameters["tls"] = "true";
                            pendingProxy.parameters["reality-public-key"] = unquoteCopy(v);
                        } else if (lk == "short-id" || lk == "shortid") {
                            pendingProxy.parameters["reality-short-id"] = unquoteCopy(v);
                        }
                    } else if (proxyNestedBlock == "plugin-opts") {
                        std::string plug = lowerAscii(pendingProxy.option("plugin"));
                        if (plug == "obfs" || plug == "obfs-local" || plug == "simple-obfs") {
                            if (lk == "mode") pendingProxy.parameters["obfs"] = unquoteCopy(v);
                            else if (lk == "host") pendingProxy.parameters["obfs-host"] = unquoteCopy(v);
                        } else if (plug == "v2ray-plugin") {
                            pendingProxy.parameters["ws"] = "true";
                            pendingProxy.parameters["network"] = "ws";
                            if (lk == "tls" && isTruthyValue(v)) pendingProxy.parameters["tls"] = "true";
                            else if (lk == "path") pendingProxy.parameters["ws-path"] = unquoteCopy(v);
                            else if (lk == "host") pendingProxy.parameters["ws-host"] = unquoteCopy(v);
                            else if (lk == "skip-cert-verify") pendingProxy.parameters["skip-cert-verify"] = unquoteCopy(v);
                        } else if (plug == "shadow-tls") {
                            if (lk == "host") pendingProxy.parameters["shadow-tls-sni"] = unquoteCopy(v);
                            else if (lk == "password") pendingProxy.parameters["shadow-tls-password"] = unquoteCopy(v);
                            else if (lk == "version") pendingProxy.parameters["shadow-tls-version"] = unquoteCopy(v);
                        }
                    } else if (proxyNestedBlock == "obfs-opts") {
                        if (lk == "mode") pendingProxy.parameters["obfs"] = unquoteCopy(v);
                        else if (lk == "host") pendingProxy.parameters["obfs-host"] = unquoteCopy(v);
                    }
                    continue;
                }

                if (lk == "<<") {
                    for (const auto &tok : parseYamlInlineArray(v)) {
                        if (!tok.empty() && tok[0] == '*') {
                            auto ait = yamlAnchors.find(tok.substr(1));
                            if (ait != yamlAnchors.end()) {
                                if (ait->second.count("plugin") && !pendingProxy.parameters.count("plugin")) {
                                    pendingProxy.parameters["plugin"] = unquoteCopy(ait->second.at("plugin"));
                                }
                                for (const auto &akv : ait->second) {
                                    if (akv.first == "name" && !pendingProxy.name.empty()) continue;
                                    if (akv.first == "server" && !pendingProxy.host.empty()) continue;
                                    if (akv.first == "port" && pendingProxy.port != 0) continue;
                                    if (akv.first == "type" && !pendingProxy.type.empty()) continue;
                                    applyClashFieldToNode(pendingProxy, akv.first, akv.second);
                                }
                            }
                        }
                    }
                    continue;
                }

                if (lk == "peers") {
                    if (!v.empty() && v.front() == '[') {
                        applyClashFieldToNode(pendingProxy, "peers", v);
                    } else {
                        inWgPeersBlock = true;
                        wgPeersIndent = indent;
                    }
                    continue;
                }

                if (v.empty() && (lk == "ws-opts" || lk == "grpc-opts" || lk == "xhttp-opts" ||
                                  lk == "splithttp-opts" || lk == "reality-opts" || lk == "plugin-opts" ||
                                  lk == "obfs-opts" || lk == "alpn" || lk == "reserved")) {
                    proxyNestedBlock = lk;
                    proxyNestedIndent = indent;
                    continue;
                }

                applyClashFieldToNode(pendingProxy, lk, v);
            }
            continue;
        }

        if (section == "proxy-groups") {
            if (trimmed[0] == '-' && (!hasPendingGroup || indent <= groupItemIndent)) {
                flushGroup();
                std::string rest = trimCopy(trimmed.substr(1));
                (void)extractLeadingYamlAnchor(rest);
                if (!rest.empty() && rest.front() == '{') {
                    auto m = parseYamlInlineMap(rest);
                    expandMergeAndAliasesInMap(m);
                    PolicyGroup g{};
                    for (const auto &kv : m) {
                        applyGroupKeyValue(g, kv.first, kv.second);
                    }
                    if (!g.name.empty()) {
                        if (out.groups.find(g.name) == out.groups.end()) {
                            out.groupOrder.push_back(g.name);
                        }
                        out.groups[g.name] = std::move(g);
                    }
                } else {
                    hasPendingGroup = true;
                    groupItemIndent = indent;
                    groupSubList.clear();
                    std::string k, v;
                    if (!rest.empty() && splitYamlKeyValue(rest, k, v)) {
                        (void)extractLeadingYamlAnchor(v);
                        applyGroupKeyValue(pendingGroup, k, v);
                    }
                }
                continue;
            }

            if (hasPendingGroup && indent > groupItemIndent) {
                if (trimmed[0] == '-') {
                    std::string member = unquoteCopy(trimmed.substr(1));
                    if (!member.empty()) {
                        if (groupSubList == "use") {
                            pendingGroup.useProviders.push_back(member);
                        } else if (groupSubList == "include-other-group") {
                            pendingGroup.includeOtherGroups.push_back(member);
                        } else {
                            pendingGroup.staticMembers.push_back(member);
                        }
                    }
                    continue;
                }
                std::string k, v;
                if (!splitYamlKeyValue(trimmed, k, v)) continue;
                (void)extractLeadingYamlAnchor(v);
                std::string lk = lowerAscii(unquoteCopy(k));
                if (!groupSubList.empty() && indent <= groupSubListIndent) {
                    groupSubList.clear();
                }
                if (v.empty() && (lk == "proxies" || lk == "use" || lk == "include-other-group")) {
                    groupSubList = lk;
                    groupSubListIndent = indent;
                    continue;
                }
                applyGroupKeyValue(pendingGroup, lk, v);
            }
            continue;
        }

        if (section == "rules" && trimmed[0] == '-') {
            std::string r = unquoteCopy(trimmed.substr(1));
            parseRuleEntry(r, out);
        }
    }

    flushProxy();
    flushGroup();
    flushProxyProvider();

    if (out.dns.nameservers.empty()) {
        out.dns.nameservers = {"1.1.1.1", "8.8.8.8"};
    }

    out.nodes = out.baseNodes;
    out.nodeOrder = out.baseNodeOrder;

    // If a Clash subscription contains `proxies:` without `proxy-groups:`, synthesize a default `Proxy` group
    if (out.groups.empty() && (!out.nodes.empty() || !out.nodeProviders.empty())) {
        PolicyGroup autoGrp{};
        autoGrp.name = "Proxy";
        autoGrp.kind = PolicyGroupKind::Select;
        autoGrp.includeAllProxies = true;
        autoGrp.staticMembers.push_back("\x01ALL");
        autoGrp.staticMembers.push_back("DIRECT");
        out.groupOrder.push_back(autoGrp.name);
        out.groups[autoGrp.name] = std::move(autoGrp);
        if (out.baseRules.empty() && out.finalPolicy == "DIRECT") {
            out.finalPolicy = "Proxy";
        }
    }

    ProfileConfigParser::recomputeDynamicGroups(out);
    registerRuleSetRefsFromBaseRules(out, ruleProviders);
    compileRulesIntoEngineProfile(out);

    if (out.nodes.empty() && out.groups.empty() && out.baseRules.empty() &&
        out.nodeProviders.empty() && out.httpPort == 0 && out.socksPort == 0 &&
        text.find("MATCH") == std::string::npos && text.find("FINAL") == std::string::npos) {
        outError = "Clash YAML contains no valid proxies, providers, groups, or rules";
        return false;
    }
    return true;
}

} // namespace

// ============================================================================
// EngineProfile Routing & Process Match Methods
// ============================================================================
std::string EngineProfile::normalizeProcessStem(const std::string &processPathOrName) {
    if (processPathOrName.empty()) return {};
    std::string s = trimCopy(unquoteCopy(processPathOrName));
    auto slash = s.find_last_of("/\\");
    if (slash != std::string::npos) s = s.substr(slash + 1);
    s = lowerAscii(std::move(s));
    if (s.size() > 4 && s.compare(s.size() - 4, 4, ".exe") == 0) {
        s.resize(s.size() - 4);
    } else if (s.size() > 4 && s.compare(s.size() - 4, 4, ".app") == 0) {
        s.resize(s.size() - 4);
    }
    return s;
}

bool EngineProfile::matchesProcessRule(const std::string &pattern, const std::string &candidatePathOrName) {
    if (pattern.empty() || candidatePathOrName.empty()) return false;
    const std::string patStem = normalizeProcessStem(pattern);
    const std::string candStem = normalizeProcessStem(candidatePathOrName);
    if (!patStem.empty() && patStem == candStem) return true;

    std::string normPat = lowerAscii(pattern);
    std::string normCand = lowerAscii(candidatePathOrName);
    std::replace(normPat.begin(), normPat.end(), '\\', '/');
    std::replace(normCand.begin(), normCand.end(), '\\', '/');
    return normCand == normPat ||
           (normCand.size() > normPat.size() &&
            normCand.compare(normCand.size() - normPat.size(), normPat.size(), normPat) == 0 &&
            (normPat.front() == '/' || normCand[normCand.size() - normPat.size() - 1] == '/'));
}

std::string EngineProfile::evaluateRoute(const std::string &host,
                                         uint16_t dstPort,
                                         const std::string &protocolName,
                                         const std::string &processPathOrName,
                                         const std::string &sourceIp) const {
    uint32_t bestCompiledOrd = UINT32_MAX;
    if (compiledRules) {
        HJRuleMatchInput minput{};
        minput.host = {reinterpret_cast<const uint8_t *>(host.data()), host.size()};
        minput.protocol_name = {reinterpret_cast<const uint8_t *>(protocolName.data()), protocolName.size()};
        if (!sourceIp.empty()) {
            minput.source_host = {reinterpret_cast<const uint8_t *>(sourceIp.data()), sourceIp.size()};
            minput.flags |= HJ_RULE_HAS_SOURCE_HOST;
        }
        minput.mode = HJ_RULE_MODE_ORDINARY;
        minput.destination_port = dstPort;
        int32_t rc = hajimi_rules_match(compiledRules.get(), &minput);
        if (rc >= 0) bestCompiledOrd = static_cast<uint32_t>(rc);
    }

    const size_t scanLimit = (bestCompiledOrd < rules.size()) ? bestCompiledOrd : rules.size();
    for (size_t i = 0; i < scanLimit; ++i) {
        const auto &r = rules[i];
        if (r.extraKind == ExtraRuleKind::ProcessName && !processPathOrName.empty()) {
            if (matchesProcessRule(r.pattern, processPathOrName)) return r.policy;
        } else if (r.extraKind == ExtraRuleKind::DomainWildcard && !host.empty()) {
            if (wildcardMatchCaseInsensitive(r.pattern, host) || safeRegexMatchName(r.pattern, host)) {
                return r.policy;
            }
        } else if (r.extraKind == ExtraRuleKind::ProtocolName && !protocolName.empty()) {
            if (lowerAscii(r.pattern) == lowerAscii(protocolName)) return r.policy;
        }
    }

    if (bestCompiledOrd < compiledOrdinalPolicies.size()) {
        return compiledOrdinalPolicies[bestCompiledOrd];
    }
    return finalPolicy.empty() ? "DIRECT" : finalPolicy;
}

// ============================================================================
// Dynamic Policy Group Re-evaluation & Provider / RuleSet Hot Injection
// ============================================================================
void ProfileConfigParser::recomputeDynamicGroups(EngineProfile &profile) {
    // Rebuild `profile.nodes` & `profile.nodeOrder` from `baseNodes` + `providerNodes`
    std::unordered_map<std::string, Node> mergedNodes = profile.baseNodes;
    std::vector<std::string> mergedOrder = profile.baseNodeOrder;

    std::unordered_map<std::string, std::vector<std::string>> providerMemberNames;
    for (const auto &np : profile.nodeProviders) {
        auto pit = profile.providerNodes.find(np.key);
        if (pit == profile.providerNodes.end()) continue;
        auto &pList = providerMemberNames[np.key];
        for (const auto &rawNd : pit->second) {
            std::string uname = rawNd.name;
            if (uname.empty()) continue;
            if (mergedNodes.find(uname) != mergedNodes.end()) {
                // Disambiguate only if host/port differs
                const auto &exist = mergedNodes[uname];
                if (exist.host != rawNd.host || exist.port != rawNd.port) {
                    for (int s = 2; s < 10000; ++s) {
                        std::string cand = uname + " #" + std::to_string(s);
                        if (mergedNodes.find(cand) == mergedNodes.end()) {
                            uname = cand;
                            break;
                        }
                    }
                }
            }
            Node copy = rawNd;
            copy.name = uname;
            if (mergedNodes.find(uname) == mergedNodes.end()) {
                mergedOrder.push_back(uname);
            }
            mergedNodes[uname] = std::move(copy);
            pList.push_back(uname);
        }
    }
    // Also merge any provider bucket registered directly by URL
    for (const auto &pkv : profile.providerNodes) {
        if (providerMemberNames.find(pkv.first) != providerMemberNames.end()) continue;
        auto &pList = providerMemberNames[pkv.first];
        for (const auto &rawNd : pkv.second) {
            if (rawNd.name.empty()) continue;
            if (mergedNodes.find(rawNd.name) == mergedNodes.end()) {
                mergedOrder.push_back(rawNd.name);
                mergedNodes[rawNd.name] = rawNd;
            }
            pList.push_back(rawNd.name);
        }
    }

    profile.nodes = std::move(mergedNodes);
    profile.nodeOrder = std::move(mergedOrder);

    auto passesFilters = [&](const PolicyGroup &grp, const std::string &candName) -> bool {
        auto nit = profile.nodes.find(candName);
        if (nit != profile.nodes.end()) {
            if (nit->second.type == "direct" || nit->second.type == "reject") return false;
            if (isExcludedByTypeFilter(grp.excludeTypeFilter, nit->second.type)) return false;
        }
        if (!grp.includeFilterRegex.empty() && !safeRegexMatchName(grp.includeFilterRegex, candName)) {
            return false;
        }
        if (!grp.excludeFilterRegex.empty() && safeRegexMatchName(grp.excludeFilterRegex, candName)) {
            return false;
        }
        return true;
    };

    auto appendUnique = [](std::vector<std::string> &vec, const std::string &item) {
        if (!item.empty() && std::find(vec.begin(), vec.end(), item) == vec.end()) {
            vec.push_back(item);
        }
    };

    std::unordered_map<std::string, std::string> savedSelections;
    for (const auto &gName : profile.groupOrder) {
        auto git = profile.groups.find(gName);
        if (git != profile.groups.end()) {
            savedSelections[gName] = git->second.selected;
            git->second.members.clear();
        }
    }

    auto rebuildSingleGroup = [&](PolicyGroup &grp, const std::string &selfName) -> bool {
        std::vector<std::string> next;
        bool sawAllSentinel = false;
        std::unordered_set<std::string> sawProvSentinels;
        std::unordered_set<std::string> sawGrpSentinels;

        auto expandAllInto = [&]() {
            for (const auto &ndName : profile.nodeOrder) {
                if (passesFilters(grp, ndName)) appendUnique(next, ndName);
            }
        };
        auto expandProvInto = [&](const std::string &provKey) {
            auto pmit = providerMemberNames.find(provKey);
            if (pmit != providerMemberNames.end()) {
                for (const auto &pn : pmit->second) {
                    if (passesFilters(grp, pn)) appendUnique(next, pn);
                }
            }
        };
        auto expandOtherGrpInto = [&](const std::string &otherName) {
            if (otherName == selfName) return;
            auto oit = profile.groups.find(otherName);
            if (oit == profile.groups.end()) return;
            for (const auto &m : oit->second.members) {
                if (m == selfName) continue;
                if (passesFilters(grp, m)) appendUnique(next, m);
            }
        };

        for (const auto &sm : grp.staticMembers) {
            if (sm == "\x01ALL") {
                sawAllSentinel = true;
                if (grp.includeAllProxies) expandAllInto();
            } else if (sm.rfind("\x01PROV:", 0) == 0) {
                std::string pk = sm.substr(6);
                sawProvSentinels.insert(pk);
                expandProvInto(pk);
            } else if (sm.rfind("\x01GRP:", 0) == 0) {
                std::string og = sm.substr(5);
                sawGrpSentinels.insert(og);
                expandOtherGrpInto(og);
            } else {
                appendUnique(next, sm);
            }
        }
        for (const auto &provKey : grp.useProviders) {
            if (!sawProvSentinels.count(provKey)) expandProvInto(provKey);
        }
        if (grp.includeAllProxies && !sawAllSentinel) {
            expandAllInto();
        }
        for (const auto &otherName : grp.includeOtherGroups) {
            if (!sawGrpSentinels.count(otherName)) expandOtherGrpInto(otherName);
        }

        if (next != grp.members) {
            grp.members = std::move(next);
            return true;
        }
        return false;
    };

    for (int iter = 0; iter < 8; ++iter) {
        bool anyChanged = false;
        for (const auto &gName : profile.groupOrder) {
            auto git = profile.groups.find(gName);
            if (git == profile.groups.end()) continue;
            if (rebuildSingleGroup(git->second, gName)) anyChanged = true;
        }
        if (!anyChanged) break;
    }

    for (const auto &gName : profile.groupOrder) {
        auto git = profile.groups.find(gName);
        if (git != profile.groups.end()) {
            git->second.selected = savedSelections[gName];
        }
    }

    // Pass 3: Ensure non-empty fallback & valid `selected` member
    for (const auto &gName : profile.groupOrder) {
        auto git = profile.groups.find(gName);
        if (git == profile.groups.end()) continue;
        auto &grp = git->second;
        if (grp.members.empty()) {
            grp.members.push_back("DIRECT");
        }
        if (grp.selected.empty() ||
            std::find(grp.members.begin(), grp.members.end(), grp.selected) == grp.members.end()) {
            grp.selected = grp.members.front();
        }
    }
}

size_t ProfileConfigParser::updateNodeProvider(EngineProfile &profile,
                                               const std::string &keyOrUrl,
                                               const std::string &content) {
    if (keyOrUrl.empty() || content.empty()) return profile.nodes.size();

    EngineProfile subParsed{};
    std::string subErr;
    std::vector<Node> extracted;
    if (parseText(content, subParsed, subErr)) {
        for (const auto &nName : subParsed.nodeOrder) {
            auto nit = subParsed.nodes.find(nName);
            if (nit != subParsed.nodes.end() && nit->second.type != "direct" && nit->second.type != "reject") {
                extracted.push_back(nit->second);
            }
        }
    }
    if (extracted.empty()) return profile.nodes.size();

    bool matchedNamed = false;
    for (const auto &np : profile.nodeProviders) {
        if (np.key == keyOrUrl || (!np.url.empty() && np.url == keyOrUrl)) {
            profile.providerNodes[np.key] = extracted;
            matchedNamed = true;
        }
    }
    if (!matchedNamed) {
        profile.providerNodes[keyOrUrl] = std::move(extracted);
    }
    recomputeDynamicGroups(profile);
    return profile.nodes.size();
}

// ============================================================================
// Share-Link Parser (`ss://`, `ssr://`, `trojan://`, `vless://`, `vmess://`,
// `hy2://`, `hysteria://`, `tuic://`, `wireguard://`, `snell://`, `mieru://`,
// `sudoku://`, `trusttunnel://`, `anytls://`, `socks5://`, `http://`)
// ============================================================================
bool ProfileConfigParser::parseShareLink(const std::string &uri, Node &outNode) {
    outNode = Node{};
    std::string s = trimCopy(uri);
    auto schemePos = s.find("://");
    if (schemePos == std::string::npos) return false;

    const std::string scheme = lowerAscii(s.substr(0, schemePos));
    std::string rest = s.substr(schemePos + 3);

    std::string remark;
    auto hashPos = rest.find('#');
    if (hashPos != std::string::npos) {
        remark = percentDecode(rest.substr(hashPos + 1));
        rest = rest.substr(0, hashPos);
    }

    if (scheme == "ssr") {
        std::string decoded;
        if (!decodeBase64Flexible(rest, decoded)) return false;
        std::string mainPart = decoded;
        std::string queryStr;
        auto qm = decoded.find("/?");
        if (qm != std::string::npos) {
            mainPart = decoded.substr(0, qm);
            queryStr = decoded.substr(qm + 2);
        } else if ((qm = decoded.find('?')) != std::string::npos) {
            mainPart = decoded.substr(0, qm);
            queryStr = decoded.substr(qm + 1);
        }
        // Format: host:port:protocol:method:obfs:base64pass (IPv6 host may contain colons so parse from right!)
        std::vector<size_t> colons;
        for (size_t i = 0; i < mainPart.size(); ++i) {
            if (mainPart[i] == ':') colons.push_back(i);
        }
        if (colons.size() < 5) return false;
        const size_t c5 = colons[colons.size() - 1];
        const size_t c4 = colons[colons.size() - 2];
        const size_t c3 = colons[colons.size() - 3];
        const size_t c2 = colons[colons.size() - 4];
        const size_t c1 = colons[colons.size() - 5];

        outNode.type = "ssr";
        outNode.host = stripInlineLineComment(mainPart.substr(0, c1), false);
        if (outNode.host.size() >= 2 && outNode.host.front() == '[' && outNode.host.back() == ']') {
            outNode.host = outNode.host.substr(1, outNode.host.size() - 2);
        }
        outNode.port = extractFirstPortFromRange(mainPart.substr(c1 + 1, c2 - c1 - 1));
        outNode.parameters["protocol"] = mainPart.substr(c2 + 1, c3 - c2 - 1);
        outNode.parameters["cipher"] = mainPart.substr(c3 + 1, c4 - c3 - 1);
        outNode.parameters["obfs"] = mainPart.substr(c4 + 1, c5 - c4 - 1);
        std::string passDec;
        if (!decodeBase64Flexible(mainPart.substr(c5 + 1), passDec)) passDec = mainPart.substr(c5 + 1);
        outNode.parameters["password"] = passDec;

        auto q = parseQueryString(queryStr);
        if (q.count("obfsparam")) {
            std::string op;
            outNode.parameters["obfs-param"] = decodeBase64Flexible(q["obfsparam"], op) ? op : q["obfsparam"];
        }
        if (q.count("protoparam")) {
            std::string pp;
            outNode.parameters["protocol-param"] = decodeBase64Flexible(q["protoparam"], pp) ? pp : q["protoparam"];
        }
        if (q.count("remarks") && remark.empty()) {
            std::string rk;
            remark = decodeBase64Flexible(q["remarks"], rk) ? rk : q["remarks"];
        }
        outNode.name = remark.empty() ? (outNode.host + ":" + std::to_string(outNode.port)) : remark;
        return !outNode.host.empty() && outNode.port != 0;
    }

    if (scheme == "vmess" && rest.find('@') == std::string::npos) {
        std::string json;
        if (!decodeBase64Flexible(rest, json)) return false;
        outNode.type = "vmess";
        outNode.host = jsonExtractString(json, "add");
        outNode.port = extractFirstPortFromRange(jsonExtractString(json, "port"));
        outNode.name = !remark.empty() ? remark : jsonExtractString(json, "ps");
        if (outNode.name.empty()) outNode.name = outNode.host + ":" + std::to_string(outNode.port);
        outNode.parameters["uuid"] = jsonExtractString(json, "id");
        std::string scy = jsonExtractString(json, "scy");
        outNode.parameters["cipher"] = scy.empty() ? "auto" : scy;
        std::string aid = jsonExtractString(json, "aid");
        if (!aid.empty()) outNode.parameters["alter-id"] = aid;
        std::string net = lowerAscii(jsonExtractString(json, "net"));
        if (!net.empty()) {
            outNode.parameters["network"] = net;
            if (net == "ws") {
                outNode.parameters["ws"] = "true";
                std::string path = jsonExtractString(json, "path");
                std::string hostHdr = jsonExtractString(json, "host");
                if (!path.empty()) outNode.parameters["ws-path"] = path;
                if (!hostHdr.empty()) outNode.parameters["ws-host"] = hostHdr;
            } else if (net == "grpc") {
                std::string path = jsonExtractString(json, "path");
                if (!path.empty()) outNode.parameters["grpc-service-name"] = path;
            }
        }
        std::string tls = lowerAscii(jsonExtractString(json, "tls"));
        if (tls == "tls" || tls == "1" || tls == "true") {
            outNode.parameters["tls"] = "true";
            std::string sni = jsonExtractString(json, "sni");
            if (sni.empty()) sni = jsonExtractString(json, "host");
            if (!sni.empty()) outNode.parameters["sni"] = sni;
        }
        return !outNode.host.empty() && outNode.port != 0 && !outNode.parameters["uuid"].empty();
    }

    std::string queryStr;
    auto qmPos = rest.find('?');
    if (qmPos != std::string::npos) {
        queryStr = rest.substr(qmPos + 1);
        rest = rest.substr(0, qmPos);
    }
    if (!rest.empty() && rest.back() == '/') rest.pop_back();
    auto query = parseQueryString(queryStr);

    if (scheme == "ss") {
        outNode.type = "ss";
        auto atPos = rest.rfind('@');
        if (atPos == std::string::npos) {
            std::string decoded;
            if (!decodeBase64Flexible(rest, decoded)) return false;
            atPos = decoded.rfind('@');
            if (atPos == std::string::npos) return false;
            std::string userInfo = decoded.substr(0, atPos);
            if (!splitHostPort(decoded.substr(atPos + 1), outNode.host, outNode.port)) return false;
            auto colon = userInfo.find(':');
            if (colon == std::string::npos) return false;
            outNode.parameters["cipher"] = userInfo.substr(0, colon);
            outNode.parameters["password"] = userInfo.substr(colon + 1);
        } else {
            std::string userPart = rest.substr(0, atPos);
            if (!splitHostPort(rest.substr(atPos + 1), outNode.host, outNode.port)) return false;
            std::string decodedUser;
            if (userPart.find(':') == std::string::npos && decodeBase64Flexible(userPart, decodedUser)) {
                userPart = decodedUser;
            } else {
                userPart = percentDecode(userPart);
            }
            auto colon = userPart.find(':');
            if (colon == std::string::npos) return false;
            outNode.parameters["cipher"] = userPart.substr(0, colon);
            outNode.parameters["password"] = userPart.substr(colon + 1);
        }
        if (query.count("plugin")) {
            std::string plug = query["plugin"];
            for (char &c : plug) if (c == ';') c = '&';
            auto pq = parseQueryString(plug);
            if (pq.count("obfs")) outNode.parameters["obfs"] = pq["obfs"];
            if (pq.count("obfs-host")) outNode.parameters["obfs-host"] = pq["obfs-host"];
        }
        outNode.name = remark.empty() ? (outNode.host + ":" + std::to_string(outNode.port)) : remark;
        return true;
    }

    auto atPos = rest.rfind('@');
    std::string userInfo;
    std::string hostPortPart = rest;
    if (atPos != std::string::npos) {
        userInfo = percentDecode(rest.substr(0, atPos));
        hostPortPart = rest.substr(atPos + 1);
    }
    if (!splitHostPort(hostPortPart, outNode.host, outNode.port)) return false;
    outNode.name = remark.empty() ? (outNode.host + ":" + std::to_string(outNode.port)) : remark;

    auto applyCommonShareQuery = [&]() {
        if (query.count("sni")) outNode.parameters["sni"] = query["sni"];
        if (query.count("peer") && !outNode.parameters.count("sni")) outNode.parameters["sni"] = query["peer"];
        if (query.count("alpn")) outNode.parameters["alpn"] = query["alpn"];
        if (query.count("fp")) outNode.parameters["client-fingerprint"] = query["fp"];
        if (query.count("insecure") && isTruthyValue(query["insecure"])) outNode.parameters["skip-cert-verify"] = "true";
        if (query.count("allowinsecure") && isTruthyValue(query["allowinsecure"])) outNode.parameters["skip-cert-verify"] = "true";
        if (query.count("type")) {
            std::string net = lowerAscii(query["type"]);
            outNode.parameters["network"] = net;
            if (net == "ws") outNode.parameters["ws"] = "true";
        }
        if (query.count("path")) {
            if (outNode.option("network") == "xhttp" || outNode.option("network") == "splithttp") {
                outNode.parameters["xhttp-path"] = query["path"];
            } else {
                outNode.parameters["ws-path"] = query["path"];
            }
        }
        if (query.count("host")) {
            if (outNode.option("network") == "xhttp" || outNode.option("network") == "splithttp") {
                outNode.parameters["xhttp-host"] = query["host"];
            } else {
                outNode.parameters["ws-host"] = query["host"];
            }
        }
        if (query.count("servicename")) outNode.parameters["grpc-service-name"] = query["servicename"];
        if (query.count("mport") || query.count("ports")) {
            std::string mp = query.count("mport") ? query["mport"] : query["ports"];
            outNode.parameters["ports"] = mp;
        }
    };

    if (scheme == "trojan") {
        outNode.type = "trojan";
        outNode.parameters["password"] = userInfo;
        outNode.parameters["tls"] = "true";
        if (query.count("security") && lowerAscii(query["security"]) == "reality") {
            outNode.parameters["security"] = "reality";
            if (query.count("pbk")) outNode.parameters["reality-public-key"] = query["pbk"];
            if (query.count("sid")) outNode.parameters["reality-short-id"] = query["sid"];
        }
        applyCommonShareQuery();
        return true;
    }
    if (scheme == "vless" || scheme == "vmess") {
        outNode.type = scheme;
        auto colon = userInfo.find(':');
        if (scheme == "vmess" && colon != std::string::npos) {
            outNode.parameters["cipher"] = userInfo.substr(0, colon);
            outNode.parameters["uuid"] = userInfo.substr(colon + 1);
        } else {
            outNode.parameters["uuid"] = userInfo;
        }
        if (query.count("flow")) outNode.parameters["flow"] = query["flow"];
        std::string sec = query.count("security") ? lowerAscii(query["security"]) : "";
        if (sec == "tls" || sec == "reality" || (query.count("tls") && isTruthyValue(query["tls"]))) {
            outNode.parameters["tls"] = "true";
            if (sec == "reality") {
                outNode.parameters["security"] = "reality";
                if (query.count("pbk")) outNode.parameters["reality-public-key"] = query["pbk"];
                if (query.count("sid")) outNode.parameters["reality-short-id"] = query["sid"];
            }
        }
        applyCommonShareQuery();
        return true;
    }
    if (scheme == "hy2" || scheme == "hysteria2") {
        outNode.type = "hysteria2";
        outNode.parameters["password"] = userInfo;
        outNode.parameters["tls"] = "true";
        if (query.count("obfs")) outNode.parameters["obfs"] = query["obfs"];
        if (query.count("obfs-password")) outNode.parameters["obfs-password"] = query["obfs-password"];
        applyCommonShareQuery();
        return true;
    }
    if (scheme == "hysteria" || scheme == "hy") {
        outNode.type = "hysteria";
        outNode.parameters["tls"] = "true";
        if (!userInfo.empty()) outNode.parameters["auth-str"] = userInfo;
        if (query.count("auth")) outNode.parameters["auth-str"] = query["auth"];
        if (query.count("upmbps")) outNode.parameters["up"] = query["upmbps"];
        if (query.count("downmbps")) outNode.parameters["down"] = query["downmbps"];
        if (query.count("obfs")) outNode.parameters["obfs"] = query["obfs"];
        applyCommonShareQuery();
        return true;
    }
    if (scheme == "tuic") {
        outNode.type = "tuic";
        outNode.parameters["tls"] = "true";
        auto colon = userInfo.find(':');
        if (colon != std::string::npos) {
            outNode.parameters["uuid"] = userInfo.substr(0, colon);
            outNode.parameters["password"] = userInfo.substr(colon + 1);
        } else {
            outNode.parameters["token"] = userInfo;
        }
        if (query.count("congestion_control")) outNode.parameters["congestion-controller"] = query["congestion_control"];
        applyCommonShareQuery();
        return true;
    }
    if (scheme == "wireguard" || scheme == "wg") {
        outNode.type = "wireguard";
        outNode.parameters["udp"] = "true";
        if (!userInfo.empty()) outNode.parameters["private-key"] = userInfo;
        if (query.count("privatekey")) outNode.parameters["private-key"] = query["privatekey"];
        if (query.count("publickey")) outNode.parameters["public-key"] = query["publickey"];
        if (query.count("presharedkey")) outNode.parameters["pre-shared-key"] = query["presharedkey"];
        if (query.count("address")) {
            for (const auto &addr : splitCsvRespectingQuotes(query["address"])) {
                auto slash = addr.find('/');
                std::string ipOnly = (slash == std::string::npos) ? addr : addr.substr(0, slash);
                if (ipOnly.find(':') != std::string::npos) outNode.parameters["ipv6"] = ipOnly;
                else outNode.parameters["ip"] = ipOnly;
            }
        }
        if (query.count("mtu")) outNode.parameters["mtu"] = query["mtu"];
        if (query.count("reserved")) outNode.parameters["reserved"] = query["reserved"];
        return true;
    }
    if (scheme == "snell") {
        outNode.type = "snell";
        if (!userInfo.empty()) outNode.parameters["psk"] = userInfo;
        if (query.count("psk")) outNode.parameters["psk"] = query["psk"];
        if (query.count("version")) outNode.parameters["version"] = query["version"];
        if (query.count("obfs")) outNode.parameters["obfs"] = query["obfs"];
        if (query.count("obfs-host")) outNode.parameters["obfs-host"] = query["obfs-host"];
        return true;
    }
    if (scheme == "anytls") {
        outNode.type = "anytls";
        outNode.parameters["password"] = userInfo;
        outNode.parameters["tls"] = "true";
        applyCommonShareQuery();
        return true;
    }
    if (scheme == "mieru") {
        outNode.type = "mieru";
        auto colon = userInfo.find(':');
        if (colon != std::string::npos) {
            outNode.parameters["username"] = userInfo.substr(0, colon);
            outNode.parameters["password"] = userInfo.substr(colon + 1);
        }
        if (query.count("transport")) outNode.parameters["transport"] = query["transport"];
        if (query.count("multiplexing")) outNode.parameters["multiplexing"] = query["multiplexing"];
        applyCommonShareQuery();
        return true;
    }
    if (scheme == "sudoku") {
        outNode.type = "sudoku";
        if (!userInfo.empty()) outNode.parameters["key"] = userInfo;
        if (query.count("key")) outNode.parameters["key"] = query["key"];
        if (query.count("cipher")) outNode.parameters["aead-method"] = query["cipher"];
        applyCommonShareQuery();
        return true;
    }
    if (scheme == "trusttunnel" || scheme == "trust-tunnel") {
        outNode.type = "trusttunnel";
        outNode.parameters["tls"] = "true";
        auto colon = userInfo.find(':');
        if (colon != std::string::npos) {
            outNode.parameters["username"] = userInfo.substr(0, colon);
            outNode.parameters["password"] = userInfo.substr(colon + 1);
        }
        if (query.count("quic")) outNode.parameters["quic"] = query["quic"];
        applyCommonShareQuery();
        return true;
    }
    if (scheme == "socks5" || scheme == "socks" || scheme == "socks5+tls" || scheme == "socks5-tls" ||
        scheme == "http" || scheme == "https") {
        outNode.type = (scheme == "http" || scheme == "https") ? "http" : "socks5";
        if (scheme == "https" || scheme == "socks5+tls" || scheme == "socks5-tls") {
            outNode.parameters["tls"] = "true";
        }
        if (!userInfo.empty()) {
            std::string decUser;
            if (userInfo.find(':') == std::string::npos && decodeBase64Flexible(userInfo, decUser)) {
                userInfo = decUser;
            }
            auto colon = userInfo.find(':');
            if (colon != std::string::npos) {
                outNode.parameters["username"] = userInfo.substr(0, colon);
                outNode.parameters["password"] = userInfo.substr(colon + 1);
            }
        }
        applyCommonShareQuery();
        return true;
    }
    return false;
}

// ============================================================================
// Auto-Detect Entry Points
// ============================================================================
bool ProfileConfigParser::parseText(const std::string &rawText, EngineProfile &outProfile, std::string &outError) {
    // Normalize lone '\r' (Classic Mac / WinUI TextBox CR) and CRLF '\r\n' to '\n'
    std::string normalized;
    normalized.reserve(rawText.size());
    for (size_t i = 0; i < rawText.size(); ++i) {
        if (rawText[i] == '\r') {
            normalized.push_back('\n');
            if (i + 1 < rawText.size() && rawText[i + 1] == '\n') {
                ++i;
            }
        } else {
            normalized.push_back(rawText[i]);
        }
    }

    std::string trimmed = trimCopy(normalized);
    if (trimmed.empty()) {
        outError = "Profile text is empty";
        return false;
    }

    // Check if single-line OR multi-line MIME-wrapped Base64 subscription payload
    std::string working = trimmed;
    if (looksLikeBase64SubscriptionPayload(trimmed)) {
        std::string decoded;
        if (decodeBase64Flexible(trimmed, decoded) && !trimCopy(decoded).empty()) {
            working.clear();
            working.reserve(decoded.size());
            for (size_t i = 0; i < decoded.size(); ++i) {
                if (decoded[i] == '\r') {
                    working.push_back('\n');
                    if (i + 1 < decoded.size() && decoded[i + 1] == '\n') ++i;
                } else {
                    working.push_back(decoded[i]);
                }
            }
            working = trimCopy(working);
        }
    }

    // Scan physical non-comment lines to distinguish Surge INI (`[Section]`) vs Clash YAML (`proxies:`)
    bool hasSurgeSectionHeader = false;
    bool hasClashRootKey = false;
    {
        std::istringstream scanStream(working);
        std::string scanLine;
        while (std::getline(scanStream, scanLine)) {
            std::string t = trimCopy(scanLine);
            if (t.empty() || t[0] == '#' || t[0] == ';') continue;
            if (t.size() >= 2 && t[0] == '/' && t[1] == '/') continue;
            if (t.front() == '[' && t.back() == ']' && t.find('=') == std::string::npos) {
                std::string sec = lowerAscii(trimCopy(t.substr(1, t.size() - 2)));
                if (sec == "general" || sec == "proxy" || sec == "proxy group" ||
                    sec == "rule" || sec == "host" || sec.rfind("wireguard ", 0) == 0) {
                    hasSurgeSectionHeader = true;
                    break;
                }
            }
            if (scanLine[0] != ' ' && scanLine[0] != '\t') {
                std::string low = lowerAscii(t);
                if (low.rfind("proxies:", 0) == 0 ||
                    low.rfind("proxy-groups:", 0) == 0 ||
                    low.rfind("proxy-providers:", 0) == 0 ||
                    low.rfind("rule-providers:", 0) == 0 ||
                    low.rfind("mixed-port:", 0) == 0) {
                    hasClashRootKey = true;
                }
            }
        }
    }

    if (hasSurgeSectionHeader) {
        return parseSurgeConf(working, outProfile, outError);
    }
    if (hasClashRootKey) {
        return parseClashYaml(working, outProfile, outError);
    }

    // Otherwise parse line-by-line share links (`ss://`, `ssr://`, `vless://`, `vmess://`, `trojan://`, `hy2://`, ...)
    outProfile = EngineProfile{};
    std::istringstream iss(working);
    std::string line;
    PolicyGroup autoGroup{};
    autoGroup.name = "Proxy";
    autoGroup.kind = PolicyGroupKind::Select;
    autoGroup.includeAllProxies = true;
    autoGroup.staticMembers.push_back("\x01ALL");
    autoGroup.staticMembers.push_back("DIRECT");

    while (std::getline(iss, line)) {
        line = trimCopy(line);
        if (line.empty() || line[0] == '#') continue;
        Node node{};
        if (parseShareLink(line, node)) {
            node.name = ensureUniqueNodeName(outProfile, node.name);
            outProfile.baseNodeOrder.push_back(node.name);
            outProfile.baseNodes[node.name] = node;
        }
    }
    if (outProfile.baseNodes.empty()) {
        outError = "Unrecognized profile format or zero valid proxy nodes";
        return false;
    }

    outProfile.nodes = outProfile.baseNodes;
    outProfile.nodeOrder = outProfile.baseNodeOrder;
    outProfile.groupOrder.push_back(autoGroup.name);
    outProfile.groups[autoGroup.name] = std::move(autoGroup);
    recomputeDynamicGroups(outProfile);
    if (!outProfile.baseNodeOrder.empty()) {
        outProfile.groups["Proxy"].selected = outProfile.baseNodeOrder.front();
    }
    outProfile.finalPolicy = "Proxy";
    compileRulesIntoEngineProfile(outProfile);
    return true;
}

bool ProfileConfigParser::parseFileUTF8(const std::string &utf8Path, EngineProfile &outProfile, std::string &outError) {
    try {
        std::string content = platform::readBoundedRegularFileUTF8(
            utf8Path, 8 * 1024 * 1024,
            "Cannot open profile file",
            "Profile path is not a regular file",
            "Profile file is empty or exceeds 8 MiB limit");
        return parseText(content, outProfile, outError);
    } catch (const std::exception &ex) {
        outError = ex.what();
        return false;
    }
}

size_t ProfileConfigParser::updateRuleSet(EngineProfile &profile,
                                          const std::string &keyOrUrl,
                                          const std::string &content) {
    if (keyOrUrl.empty()) return profile.rules.size();

    bool matchedNamed = false;
    for (const auto &rs : profile.ruleSets) {
        if (rs.key == keyOrUrl || (!rs.url.empty() && rs.url == keyOrUrl)) {
            profile.ruleSetContents[rs.key] = content;
            matchedNamed = true;
        }
    }
    if (!matchedNamed) {
        profile.ruleSetContents[keyOrUrl] = content;
    }
    compileRulesIntoEngineProfile(profile);
    return profile.rules.size();
}

} // namespace hajimi::engine
