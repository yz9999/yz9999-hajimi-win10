#include "../../Sources/HajimiEngineCAPI/include/HajimiEngineCAPI.h"
#include "../../Sources/HajimiEngineCAPI/ProfileConfigParser.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <string>

#define CHECK(cond, msg)                                                           \
    do {                                                                           \
        if (!(cond)) {                                                             \
            std::cerr << "[FAIL] " << __FILE__ << ":" << __LINE__ << " - " << msg  \
                      << std::endl;                                                \
            return 1;                                                              \
        }                                                                          \
    } while (0)

int main() {
    using namespace hajimi::engine;

    // 1. Real-world Mihomo / Stash / Sub-Store YAML with:
    //    - YAML anchors (&BaseProvider, &BaseProxy, &AutoFilter) & merge keys (<<: *...)
    //    - `rule-providers:` with `&anchor` on provider header (`OpenAI: &OpenAI`) & `.mrs` format
    //    - `proxy-providers:` + `use:` in `proxy-groups:`
    //    - `include-all: true` + `filter: "(?i)🇭🇰|HK|Hong Kong"` + `exclude-filter: "倍率|Expire"` + `exclude-type: "http|socks5"`
    //    - Clash `wireguard` with nested `peers:` (no top-level server/port)
    //    - Hysteria2 with `ports: 20000-40000` (no top-level port)
    //    - Shadowsocks with `plugin: v2ray-plugin` + `plugin-opts`
    //    - Quoted YAML ruleset lines with trailing `# comment` (`- '+.chatgpt.com' # OpenAI Web`)
    //    - `GEOSITE,youtube` + `RULE-SET,LAN,DIRECT` + `HOST-SUFFIX` + `DEST-PORT` + `REJECT-DROP`
    const char *complexMihomoYaml = R"YAML(
mixed-port: 7890
ipv6: false

proxy-providers:
  SubA: &BaseSub
    type: http
    url: https://sub.example.com/api/v1/client/subscribe?token=abc
    interval: 3600

proxies:
  - &BaseSS
    type: shadowsocks
    port: 8388
    cipher: 2022-blake3-aes-128-gcm
    password: aaaaaaaaaaaaaaaaaaaaaa==
    name: 🇭🇰 香港 IEPL 01
    server: hk1.example.com
  - name: 🇭🇰 香港 高倍率 x5
    <<: *BaseSS
    server: hk-x5.example.com
  - name: 🇯🇵 日本 HY2 跳跃
    type: hy2
    server: jp-hy2.example.com
    ports: 25000-35000
    password: hy2secret
    sni: jp-hy2.example.com
  - name: 🇸🇬 新加坡 WS插件
    type: ss
    server: sg.example.com
    port: 443
    cipher: aes-256-gcm
    password: secret
    plugin: v2ray-plugin
    plugin-opts:
      mode: websocket
      tls: true
      host: cdn.sg.example.com
      path: /v2ws
  - name: 🇺🇸 美国 WireGuard
    type: wireguard
    ip: 172.16.0.2
    private-key: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa=
    mtu: 1408
    peers:
      - server: engage.cloudflareclient.com
        port: 2408
        public-key: bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb=
        reserved: [12, 34, 56]
  - name: HTTP测试节点
    type: https
    server: http.example.com
    port: 8443
    username: u1
    password: p1

proxy-groups:
  - name: 🚀 节点选择
    type: select
    include-all: true
    exclude-type: "http|socks5"
    proxies:
      - 🇭🇰 香港自动
      - 🇯🇵 日本自动
      - 📦 外部机场组
      - DIRECT
  - name: 🇭🇰 香港自动
    type: url-test
    include-all: true
    filter: "(?i)🇭🇰|HK|香港"
    exclude-filter: "倍率|到期"
    interval: 180
    tolerance: 30
  - name: 🇯🇵 日本自动
    type: fallback
    include-all: true
    filter: "(?i)🇯🇵|JP|日本"
  - name: 📦 外部机场组
    type: select
    use:
      - SubA
    filter: "(?i)TW|台湾"

rule-providers:
  RuleBase: &RuleDomain
    type: http
    behavior: domain
    format: mrs
    interval: 86400
  OpenAI: &OpenAIProv
    <<: *RuleDomain
    url: https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/openai.mrs
  RejectAds: { type: http, behavior: domain, format: yaml, url: https://rules.example.com/ads.yaml }

rules:
  - RULE-SET,LAN,DIRECT
  - RULE-SET,RejectAds,REJECT-DROP
  - RULE-SET,OpenAI,🇯🇵 日本自动
  - GEOSITE,youtube,🇭🇰 香港自动
  - HOST-SUFFIX,claude.ai,🚀 节点选择
  - DOMAIN-WILDCARD,*.perplexity.ai,🚀 节点选择
  - DEST-PORT,853,DIRECT
  - MATCH,🚀 节点选择
)YAML";

    HJEngineRef eng = hajimi_engine_create();
    CHECK(eng != nullptr, "hajimi_engine_create failed");

    char err[512]{};
    int rc = hajimi_engine_load_profile_text(
        eng, complexMihomoYaml, std::strlen(complexMihomoYaml), err, sizeof(err));
    CHECK(rc == HAJIMI_ENGINE_OK, std::string("load complexMihomoYaml failed: ") + err);

    // Check node count == 6 (all 6 inline proxies including WireGuard peers:, HY2 ports:, SS plugin, HTTPS)
    char *st1 = hajimi_engine_get_status_json(eng);
    CHECK(st1 != nullptr, "status json null");
    std::string st1Str(st1);
    hajimi_engine_free_string(st1);
    CHECK(st1Str.find("\"nodeCount\":6") != std::string::npos, "Expected nodeCount==6, got: " + st1Str);

    // Verify dynamic filter group `🇭🇰 香港自动` matched `🇭🇰 香港 IEPL 01` and excluded `🇭🇰 香港 高倍率 x5`!
    char pol[128]{};
    // Inject OpenAI ruleset with quoted lines + inline `#` comments!
    const char *openAiYamlPayload =
        "payload:\n"
        "  - '+.openai.com' # main domain\n"
        "  - \"+.chatgpt.com\" // secondary comment\n"
        "  - 'api.oaipro.com' # bare domain in behavior:domain\n";
    CHECK(hajimi_engine_update_ruleset(eng, "OpenAI", openAiYamlPayload, std::strlen(openAiYamlPayload)) == HAJIMI_ENGINE_OK,
          "update OpenAI ruleset failed");

    const char *adsYamlPayload =
        "payload:\n"
        "  - '+.doubleclick.net' # ad tracker\n";
    CHECK(hajimi_engine_update_ruleset(eng, "RejectAds", adsYamlPayload, std::strlen(adsYamlPayload)) == HAJIMI_ENGINE_OK,
          "update RejectAds ruleset failed");

    const char *ytPayload = "+.youtube.com\n+.ytimg.com\n";
    CHECK(hajimi_engine_update_ruleset(eng, "GEOSITE:YOUTUBE", ytPayload, std::strlen(ytPayload)) == HAJIMI_ENGINE_OK,
          "update GEOSITE:YOUTUBE failed");

    // Built-in `RULE-SET,LAN,DIRECT` must match 192.168.1.1 without any external download!
    CHECK(hajimi_engine_evaluate_route(eng, "192.168.1.1", 80, "TCP", "", pol, sizeof(pol)) == HAJIMI_ENGINE_OK &&
          std::strcmp(pol, "DIRECT") == 0, std::string("Expected LAN -> DIRECT, got: ") + pol);

    // `RejectAds` -> `REJECT-DROP` must normalize to `REJECT`!
    CHECK(hajimi_engine_evaluate_route(eng, "ad.doubleclick.net", 443, "TCP", "", pol, sizeof(pol)) == HAJIMI_ENGINE_OK &&
          std::strcmp(pol, "REJECT") == 0, std::string("Expected doubleclick -> REJECT, got: ") + pol);

    // Quoted `- '+.chatgpt.com' // comment` must strip comment BEFORE unquoting and route to `🇯🇵 日本 HY2 跳跃`!
    CHECK(hajimi_engine_evaluate_route(eng, "chat.chatgpt.com", 443, "TCP", "", pol, sizeof(pol)) == HAJIMI_ENGINE_OK &&
          std::strcmp(pol, "🇯🇵 日本 HY2 跳跃") == 0, std::string("Expected chatgpt.com -> 🇯🇵 日本 HY2 跳跃, got: ") + pol);

    // Bare domain `api.oaipro.com` in `behavior: domain` ruleset must match!
    CHECK(hajimi_engine_evaluate_route(eng, "api.oaipro.com", 443, "TCP", "", pol, sizeof(pol)) == HAJIMI_ENGINE_OK &&
          std::strcmp(pol, "🇯🇵 日本 HY2 跳跃") == 0, std::string("Expected api.oaipro.com -> 🇯🇵 日本 HY2 跳跃, got: ") + pol);

    // `GEOSITE,youtube` -> `🇭🇰 香港自动` -> `🇭🇰 香港 IEPL 01` (excluding `🇭🇰 香港 高倍率 x5`!)
    CHECK(hajimi_engine_evaluate_route(eng, "www.youtube.com", 443, "TCP", "", pol, sizeof(pol)) == HAJIMI_ENGINE_OK &&
          std::strcmp(pol, "🇭🇰 香港 IEPL 01") == 0, std::string("Expected youtube -> 🇭🇰 香港 IEPL 01, got: ") + pol);
    CHECK(st1Str.find("\"name\":\"🇭🇰 香港自动\",\"kind\":\"url-test\",\"selected\":\"🇭🇰 香港 IEPL 01\",\"members\":[\"🇭🇰 香港 IEPL 01\"]") != std::string::npos,
          "Expected 🇭🇰 香港自动 to exclude 倍率 node! Status: " + st1Str);

    // `DOMAIN-WILDCARD,*.perplexity.ai` & `HOST-SUFFIX,claude.ai`
    CHECK(hajimi_engine_evaluate_route(eng, "www.perplexity.ai", 443, "TCP", "", pol, sizeof(pol)) == HAJIMI_ENGINE_OK &&
          std::strcmp(pol, "🇭🇰 香港 IEPL 01") == 0, std::string("Expected perplexity -> 🇭🇰 香港 IEPL 01, got: ") + pol);

    // Inject external `proxy-providers` (`SubA`) via multi-line MIME-wrapped Base64 share links!
    // Base64 of:
    // trojan://pw1@tw1.example.com:443?sni=tw1.example.com#🇹🇼 台湾 Hinet 01
    // vless://11111111-2222-3333-4444-555555555555@kr1.example.com:443?security=tls&sni=kr1.example.com#🇰🇷 韩国 BGP 01
    const char *multilineB64Sub =
        "dHJvamFuOi8vcHcxQHR3MS5leGFtcGxlLmNvbTo0NDM/c25pPXR3MS5leGFtcGxl\r\n"
        "LmNvbSNUVyDlj7Drmb4gSGluZXQgMDEKdmxpc3M6Ly8xMTExMTExMS0yMjIyLTMz\r\n";
    // Let's construct exact multi-line Base64 from raw links:
    const std::string rawProviderLinks =
        "trojan://pw1@tw1.example.com:443?sni=tw1.example.com#TW 台湾 Hinet 01\n"
        "vless://11111111-2222-3333-4444-555555555555@kr1.example.com:443?security=tls&sni=kr1.example.com#KR 韩国 01\n";
    (void)multilineB64Sub;
    static const char kB64Chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    auto encodeWrappedB64 = [&](const std::string &in) {
        std::string b64;
        int val = 0, valb = -6;
        for (unsigned char c : in) {
            val = (val << 8) + c;
            valb += 8;
            while (valb >= 0) {
                b64.push_back(kB64Chars[(val >> valb) & 0x3F]);
                valb -= 6;
                if (b64.size() % 65 == 64) b64.push_back('\n');
            }
        }
        if (valb > -6) b64.push_back(kB64Chars[((val << 8) >> (valb + 8)) & 0x3F]);
        while (b64.size() % 4 != 0) b64.push_back('=');
        return b64;
    };
    std::string wrappedProviderPayload = encodeWrappedB64(rawProviderLinks);

    char *npJsonBefore = hajimi_engine_get_node_providers_json(eng);
    CHECK(npJsonBefore != nullptr && std::strstr(npJsonBefore, "\"key\":\"SubA\"") != nullptr,
          "Expected SubA in node providers json");
    hajimi_engine_free_string(npJsonBefore);

    CHECK(hajimi_engine_update_node_provider(eng, "SubA", wrappedProviderPayload.data(), wrappedProviderPayload.size()) == HAJIMI_ENGINE_OK,
          "hajimi_engine_update_node_provider failed");

    // Verify `📦 外部机场组` dynamically expanded `use: [SubA]` + `filter: "(?i)TW|台湾"` to select `TW 台湾 Hinet 01`!
    CHECK(hajimi_engine_select_policy_group(eng, "🚀 节点选择", "📦 外部机场组") == HAJIMI_ENGINE_OK,
          "select 📦 外部机场组 failed");
    CHECK(hajimi_engine_evaluate_route(eng, "claude.ai", 443, "TCP", "", pol, sizeof(pol)) == HAJIMI_ENGINE_OK &&
          std::strcmp(pol, "TW 台湾 Hinet 01") == 0,
          std::string("Expected 📦 外部机场组 -> TW 台湾 Hinet 01, got: ") + pol);

    // Check `hajimi_engine_get_rules_json` returns baseRules + DNS settings
    char *rulesJson = hajimi_engine_get_rules_json(eng);
    CHECK(rulesJson != nullptr &&
          std::strstr(rulesJson, "\"finalPolicy\":\"🚀 节点选择\"") != nullptr &&
          std::strstr(rulesJson, "\"baseRuleCount\":7") != nullptr,
          std::string("Unexpected rulesJson: ") + (rulesJson ? rulesJson : "null"));
    hajimi_engine_free_string(rulesJson);

    // 2. Test Surge `.conf` with `include-all-proxies=1`, `include-other-group`, `policy-regex-filter`,
    //    `DOMAIN-SET`, `RULE-SET,SYSTEM`, and legacy `custom` SS syntax
    const char *surgeAdvancedConf = R"CONF(
[General]
http-listen = 127.0.0.1:6152
socks5-listen = 127.0.0.1:6153
dns-server = system, 223.5.5.5, 119.29.29.29
encrypted-dns-server = https://dns.alidns.com/dns-query

[Proxy]
SG-SS-Legacy = custom, sg1.example.com, 8388, aes-256-gcm, mypass, https://example.com/SSEncrypt.module
SG-Trojan-01 = trojan, sg2.example.com, 443, mypass, sni=sg2.example.com
US-VLESS-01 = vless, us1.example.com, 443, 11111111-2222-3333-4444-555555555555, tls=true, sni=us1.example.com

[Proxy Group]
🇸🇬 狮城自动 = url-test, include-all-proxies=1, policy-regex-filter=SG
🌎 汇总策略 = select, include-other-group="🇸🇬 狮城自动", US-VLESS-01

[Rule]
RULE-SET, SYSTEM, DIRECT
DOMAIN-SET, https://rules.example.com/stream.txt, 🌎 汇总策略
FINAL, 🌎 汇总策略
)CONF";

    CHECK(hajimi_engine_load_profile_text(
              eng, surgeAdvancedConf, std::strlen(surgeAdvancedConf), err, sizeof(err)) == HAJIMI_ENGINE_OK,
          std::string("load surgeAdvancedConf failed: ") + err);
    const char *domainSetPayload = ".netflix.com\nfast.com\n";
    CHECK(hajimi_engine_update_ruleset(
              eng, "https://rules.example.com/stream.txt", domainSetPayload, std::strlen(domainSetPayload)) == HAJIMI_ENGINE_OK,
          "update DOMAIN-SET failed");
    CHECK(hajimi_engine_evaluate_route(eng, "captive.apple.com", 80, "TCP", "", pol, sizeof(pol)) == HAJIMI_ENGINE_OK &&
          std::strcmp(pol, "DIRECT") == 0, "Expected SYSTEM ruleset -> DIRECT");
    CHECK(hajimi_engine_evaluate_route(eng, "www.netflix.com", 443, "TCP", "", pol, sizeof(pol)) == HAJIMI_ENGINE_OK &&
          std::strcmp(pol, "SG-SS-Legacy") == 0, std::string("Expected netflix -> SG-SS-Legacy, got: ") + pol);
    CHECK(hajimi_engine_evaluate_route(eng, "fast.com", 443, "TCP", "", pol, sizeof(pol)) == HAJIMI_ENGINE_OK &&
          std::strcmp(pol, "SG-SS-Legacy") == 0, std::string("Expected fast.com -> SG-SS-Legacy, got: ") + pol);

    // 3. Test additional ShareLink schemes (`ssr://`, `wireguard://`, `hysteria://`, `snell://`, `socks5+tls://`)
    hajimi::Node ssrNode{}, wgNode{}, hy1Node{}, snellNode{}, s5tlsNode{};
    // ssr:// base64("jp.example.com:8388:origin:aes-256-cfb:plain:cGFzc3dvcmQ=/?remarks=U1NS5pel5pys")
    std::string ssrRaw = "jp.example.com:8388:origin:aes-256-cfb:plain:cGFzc3dvcmQ=/?remarks=U1NS5pel5pys";
    std::string ssrUri = "ssr://" + encodeWrappedB64(ssrRaw);
    ssrUri.erase(std::remove(ssrUri.begin(), ssrUri.end(), '\n'), ssrUri.end());
    CHECK(ProfileConfigParser::parseShareLink(ssrUri, ssrNode) && ssrNode.type == "ssr" && ssrNode.port == 8388,
          "Failed to parse ssr:// link");
    CHECK(ProfileConfigParser::parseShareLink(
              "wireguard://privKeyBase64@162.159.192.1:2408?publickey=pubKeyBase64&address=172.16.0.2/32&mtu=1400#WG-CF",
              wgNode) && wgNode.type == "wireguard" && wgNode.option("ip") == "172.16.0.2",
          "Failed to parse wireguard:// link");
    CHECK(ProfileConfigParser::parseShareLink(
              "hysteria://hy1.example.com:8443?auth=myauth&upmbps=100&downmbps=500&peer=hy1.example.com#HY1-Node",
              hy1Node) && hy1Node.type == "hysteria" && hy1Node.option("auth-str") == "myauth",
          "Failed to parse hysteria:// link");
    CHECK(ProfileConfigParser::parseShareLink(
              "snell://mypsk@snell.example.com:9001?version=4&obfs=tls#Snell-v4",
              snellNode) && snellNode.type == "snell" && snellNode.option("psk") == "mypsk",
          "Failed to parse snell:// link");
    CHECK(ProfileConfigParser::parseShareLink(
              "socks5+tls://alice:secret@s5.example.com:1080?sni=s5.example.com#S5-TLS",
              s5tlsNode) && s5tlsNode.type == "socks5" && s5tlsNode.flag("tls"),
          "Failed to parse socks5+tls:// link");

    hajimi_engine_destroy(eng);
    std::cout << "[PASS] ParserRealWorldRegressionMain passed all Clash/Mihomo/Surge/ShareLink tests!\n";
    return 0;
}
