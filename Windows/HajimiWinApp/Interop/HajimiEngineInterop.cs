using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Win32.SafeHandles;

[assembly: DefaultDllImportSearchPaths(DllImportSearchPath.ApplicationDirectory | DllImportSearchPath.System32)]

namespace HajimiWinApp.Interop;

public enum OutboundRoutingMode : int
{
    Rule = 0,
    Global = 1,
    Direct = 2
}

[StructLayout(LayoutKind.Sequential)]
internal unsafe struct NativeListenerConfig
{
    public byte* BindHostUtf8;
    public ushort HttpPort;
    public ushort SocksPort;
    public ushort ControllerPort;
    public ushort DnsListenPort;
    public byte* ControllerKeyUtf8;
    public byte* OutboundIfNameUtf8;
}

internal static partial class HajimiNativeMethods
{
    private const string DllName = "HajimiEngine";

    [LibraryImport(DllName, EntryPoint = "hajimi_engine_version")]
    internal static partial IntPtr EngineVersionPtr();

    [LibraryImport(DllName, EntryPoint = "hajimi_engine_create")]
    internal static partial IntPtr EngineCreate();

    [LibraryImport(DllName, EntryPoint = "hajimi_engine_destroy")]
    internal static partial void EngineDestroy(IntPtr engine);

    [LibraryImport(DllName, EntryPoint = "hajimi_engine_load_profile_text")]
    internal static unsafe partial int EngineLoadProfileText(
        IntPtr engine, byte* textUtf8, nuint textLen, byte* errBuf, nuint errCap);

    [LibraryImport(DllName, EntryPoint = "hajimi_engine_load_profile_file")]
    internal static unsafe partial int EngineLoadProfileFile(
        IntPtr engine, byte* pathUtf8, byte* errBuf, nuint errCap);

    [LibraryImport(DllName, EntryPoint = "hajimi_engine_start")]
    internal static unsafe partial int EngineStart(
        IntPtr engine, NativeListenerConfig* cfg, byte* errBuf, nuint errCap);

    [LibraryImport(DllName, EntryPoint = "hajimi_engine_stop")]
    internal static partial void EngineStop(IntPtr engine);

    [LibraryImport(DllName, EntryPoint = "hajimi_engine_bound_http_port")]
    internal static partial ushort BoundHttpPort(IntPtr engine);

    [LibraryImport(DllName, EntryPoint = "hajimi_engine_bound_socks_port")]
    internal static partial ushort BoundSocksPort(IntPtr engine);

    [LibraryImport(DllName, EntryPoint = "hajimi_engine_set_outbound_mode")]
    internal static partial int SetOutboundMode(IntPtr engine, int mode);

    [LibraryImport(DllName, EntryPoint = "hajimi_engine_get_outbound_mode")]
    internal static partial int GetOutboundMode(IntPtr engine);

    [LibraryImport(DllName, EntryPoint = "hajimi_engine_select_policy_group")]
    internal static unsafe partial int SelectPolicyGroup(
        IntPtr engine, byte* groupUtf8, byte* memberUtf8);

    [LibraryImport(DllName, EntryPoint = "hajimi_engine_set_global_node")]
    internal static unsafe partial int SetGlobalNode(
        IntPtr engine, byte* nodeUtf8);

    [LibraryImport(DllName, EntryPoint = "hajimi_engine_get_global_node")]
    internal static unsafe partial int GetGlobalNode(
        IntPtr engine, byte* outNodeUtf8, nuint outCap);

    [LibraryImport(DllName, EntryPoint = "hajimi_engine_evaluate_route")]
    internal static unsafe partial int EvaluateRoute(
        IntPtr engine, byte* hostUtf8, ushort dstPort, byte* protoUtf8, byte* procUtf8, byte* outPolicy, nuint outCap);

    [LibraryImport(DllName, EntryPoint = "hajimi_engine_probe_node_latency_ms")]
    internal static unsafe partial int ProbeNodeLatencyMs(
        IntPtr engine, byte* nodeUtf8, uint timeoutMs);

    [LibraryImport(DllName, EntryPoint = "hajimi_engine_probe_all_nodes")]
    internal static partial int ProbeAllNodes(IntPtr engine, uint timeoutMs);

    [LibraryImport(DllName, EntryPoint = "hajimi_engine_get_rulesets_json")]
    internal static partial IntPtr GetRuleSetsJson(IntPtr engine);

    [LibraryImport(DllName, EntryPoint = "hajimi_engine_update_ruleset")]
    internal static unsafe partial int UpdateRuleSet(
        IntPtr engine, byte* keyOrUrlUtf8, byte* contentUtf8, nuint contentLen);

    [LibraryImport(DllName, EntryPoint = "hajimi_engine_get_node_providers_json")]
    internal static partial IntPtr GetNodeProvidersJson(IntPtr engine);

    [LibraryImport(DllName, EntryPoint = "hajimi_engine_update_node_provider")]
    internal static unsafe partial int UpdateNodeProvider(
        IntPtr engine, byte* keyOrUrlUtf8, byte* contentUtf8, nuint contentLen);

    [LibraryImport(DllName, EntryPoint = "hajimi_engine_get_rules_json")]
    internal static partial IntPtr GetRulesJson(IntPtr engine);

    [LibraryImport(DllName, EntryPoint = "hajimi_engine_notify_network_change")]
    internal static unsafe partial void NotifyNetworkChange(
        IntPtr engine, byte* newOutboundIfUtf8);

    [LibraryImport(DllName, EntryPoint = "hajimi_engine_flush_dns_cache")]
    internal static partial void FlushDnsCache(IntPtr engine);

    [LibraryImport(DllName, EntryPoint = "hajimi_engine_flush_fakeip")]
    internal static partial void FlushFakeIp(IntPtr engine);

    [LibraryImport(DllName, EntryPoint = "hajimi_engine_attach_shm_tunnel")]
    internal static partial int AttachShmTunnel(
        IntPtr engine, IntPtr shmBaseAddress, nuint rxEvent, nuint txEvent, uint framePrefixLen);

    [LibraryImport(DllName, EntryPoint = "hajimi_engine_detach_tunnel")]
    internal static partial void DetachTunnel(IntPtr engine);

    [LibraryImport(DllName, EntryPoint = "hajimi_engine_get_status_json")]
    internal static partial IntPtr GetStatusJson(IntPtr engine);

    [LibraryImport(DllName, EntryPoint = "hajimi_engine_get_connections_json")]
    internal static partial IntPtr GetConnectionsJson(IntPtr engine);

    [LibraryImport(DllName, EntryPoint = "hajimi_engine_close_connection")]
    internal static partial int CloseConnection(IntPtr engine, ulong connectionId);

    [LibraryImport(DllName, EntryPoint = "hajimi_engine_get_logs_json")]
    internal static partial IntPtr GetLogsJson(IntPtr engine, ulong sinceSeq);

    [LibraryImport(DllName, EntryPoint = "hajimi_engine_run_diagnostics_json")]
    internal static partial IntPtr RunDiagnosticsJson(IntPtr engine);

    [LibraryImport(DllName, EntryPoint = "hajimi_engine_free_string")]
    internal static partial void FreeEngineString(IntPtr heapStr);

    [LibraryImport(DllName, EntryPoint = "hajimi_win_sysproxy_enable")]
    internal static unsafe partial int WinSysProxyEnable(
        byte* snapshotDirUtf8, byte* hostUtf8, ushort port, byte* bypassUtf8, byte* errBuf, nuint errCap);

    [LibraryImport(DllName, EntryPoint = "hajimi_win_sysproxy_repoint")]
    internal static unsafe partial int WinSysProxyRepoint(
        byte* snapshotDirUtf8, byte* hostUtf8, ushort port, byte* errBuf, nuint errCap);

    [LibraryImport(DllName, EntryPoint = "hajimi_win_sysproxy_disable")]
    internal static unsafe partial int WinSysProxyDisable(
        byte* snapshotDirUtf8, byte* errBuf, nuint errCap);

    [LibraryImport(DllName, EntryPoint = "hajimi_win_sysproxy_is_owned")]
    internal static unsafe partial int WinSysProxyIsOwned(byte* snapshotDirUtf8);
}

public sealed class PolicyGroupDto
{
    [JsonPropertyName("name")] public string Name { get; set; } = "";
    [JsonPropertyName("kind")] public string Kind { get; set; } = "select";
    [JsonPropertyName("selected")] public string Selected { get; set; } = "";
    [JsonPropertyName("members")] public List<string> Members { get; set; } = [];

    [JsonIgnore]
    public string KindLabel => Kind switch
    {
        "url-test" => "URL-TEST 自动最低延迟",
        "fallback" => "FALLBACK 故障转移",
        "load-balance" => "LOAD-BALANCE 负载均衡",
        "smart" => "SMART UCB1 智能优选",
        _ => "SELECT 手动选择"
    };
}

public sealed class ProxyNodeDto
{
    [JsonPropertyName("name")] public string Name { get; set; } = "";
    [JsonPropertyName("type")] public string Type { get; set; } = "";
    [JsonPropertyName("server")] public string Server { get; set; } = "";
    [JsonPropertyName("port")] public ushort Port { get; set; }
    [JsonPropertyName("network")] public string Network { get; set; } = "tcp";
    [JsonPropertyName("dialerProxy")] public string DialerProxy { get; set; } = "";

    [JsonIgnore] public int LatencyMs { get; set; } = int.MinValue;
    [JsonIgnore] public string TypeBadge => string.IsNullOrEmpty(Network) || Network == "tcp"
        ? Type.ToUpperInvariant()
        : $"{Type.ToUpperInvariant()} · {Network.ToUpperInvariant()}";
    [JsonIgnore] public string EndpointText => string.IsNullOrEmpty(DialerProxy)
        ? $"{Server}:{Port}"
        : $"{Server}:{Port}  (前置: {DialerProxy})";
    [JsonIgnore] public string LatencyText => LatencyMs == int.MinValue
        ? "待测速"
        : (LatencyMs >= 0 ? $"{LatencyMs} ms" : "超时");
}

public sealed class EngineStatusSnapshot
{
    [JsonPropertyName("version")] public string Version { get; set; } = "";
    [JsonPropertyName("running")] public bool Running { get; set; }
    [JsonPropertyName("mode")] public string Mode { get; set; } = "rule";
    [JsonPropertyName("httpPort")] public ushort HttpPort { get; set; }
    [JsonPropertyName("socksPort")] public ushort SocksPort { get; set; }
    [JsonPropertyName("controllerPort")] public ushort ControllerPort { get; set; }
    [JsonPropertyName("uploadedBytes")] public ulong UploadedBytes { get; set; }
    [JsonPropertyName("downloadedBytes")] public ulong DownloadedBytes { get; set; }
    [JsonPropertyName("uploadBps")] public ulong UploadBps { get; set; }
    [JsonPropertyName("downloadBps")] public ulong DownloadBps { get; set; }
    [JsonPropertyName("peakBps")] public ulong PeakBps { get; set; }
    [JsonPropertyName("p95Bps")] public ulong P95Bps { get; set; }
    [JsonPropertyName("activeConnections")] public uint ActiveConnections { get; set; }
    [JsonPropertyName("totalConnections")] public ulong TotalConnections { get; set; }
    [JsonPropertyName("activeTcpFlows")] public uint ActiveTcpFlows { get; set; }
    [JsonPropertyName("activeUdpSessions")] public uint ActiveUdpSessions { get; set; }
    [JsonPropertyName("dnsQueries")] public ulong DnsQueries { get; set; }
    [JsonPropertyName("fakeIpHits")] public ulong FakeIpHits { get; set; }
    [JsonPropertyName("dnsCacheHits")] public ulong DnsCacheHits { get; set; }
    [JsonPropertyName("nodeCount")] public int NodeCount { get; set; }
    [JsonPropertyName("ruleCount")] public int RuleCount { get; set; }
    [JsonPropertyName("ruleSetCount")] public int RuleSetCount { get; set; }
    [JsonPropertyName("loadedRuleSetCount")] public int LoadedRuleSetCount { get; set; }
    [JsonPropertyName("globalSelectedNode")] public string GlobalSelectedNode { get; set; } = "__AUTO_FASTEST__";
    [JsonPropertyName("effectiveGlobalNode")] public string EffectiveGlobalNode { get; set; } = "DIRECT";
    [JsonPropertyName("groups")] public List<PolicyGroupDto> Groups { get; set; } = [];
    [JsonPropertyName("nodes")] public List<ProxyNodeDto> Nodes { get; set; } = [];
    [JsonPropertyName("nodeLatencies")] public Dictionary<string, int> NodeLatencies { get; set; } = [];
    [JsonPropertyName("bypassServerIps")] public List<string> BypassServerIps { get; set; } = [];
}

public sealed class ActiveConnectionDto
{
    [JsonPropertyName("id")] public ulong Id { get; set; }
    [JsonPropertyName("proto")] public string Proto { get; set; } = "";
    [JsonPropertyName("process")] public string Process { get; set; } = "";
    [JsonPropertyName("host")] public string Host { get; set; } = "";
    [JsonPropertyName("port")] public ushort Port { get; set; }
    [JsonPropertyName("policy")] public string Policy { get; set; } = "";
    [JsonPropertyName("upBytes")] public ulong UpBytes { get; set; }
    [JsonPropertyName("downBytes")] public ulong DownBytes { get; set; }
    [JsonPropertyName("ageMs")] public long AgeMs { get; set; }

    [JsonIgnore] public string ProcessLabel => string.IsNullOrWhiteSpace(Process) ? "System / Local" : Path.GetFileName(Process);
    [JsonIgnore] public string EndpointText => $"{Host}:{Port}";
    [JsonIgnore] public string TrafficText => $"↑ {FormatBytes(UpBytes)}   ↓ {FormatBytes(DownBytes)}";

    private static string FormatBytes(ulong b)
    {
        if (b < 1024) return $"{b} B";
        if (b < 1024 * 1024) return $"{b / 1024.0:F1} KB";
        if (b < 1024UL * 1024 * 1024) return $"{b / (1024.0 * 1024.0):F1} MB";
        return $"{b / (1024.0 * 1024.0 * 1024.0):F2} GB";
    }
}

public sealed class EngineLogEntryDto
{
    [JsonPropertyName("seq")] public ulong Seq { get; set; }
    [JsonPropertyName("time")] public string Time { get; set; } = "";
    [JsonPropertyName("level")] public string Level { get; set; } = "INFO";
    [JsonPropertyName("msg")] public string Msg { get; set; } = "";
}

public sealed class EngineLogBatchDto
{
    [JsonPropertyName("nextSeq")] public ulong NextSeq { get; set; }
    [JsonPropertyName("logs")] public List<EngineLogEntryDto> Logs { get; set; } = [];
}

public sealed class RuleSetRefDto
{
    [JsonPropertyName("key")] public string Key { get; set; } = "";
    [JsonPropertyName("url")] public string Url { get; set; } = "";
    [JsonPropertyName("policy")] public string Policy { get; set; } = "";
    [JsonPropertyName("behavior")] public string Behavior { get; set; } = "classical";
    [JsonPropertyName("format")] public string Format { get; set; } = "text";
    [JsonPropertyName("loaded")] public bool Loaded { get; set; }

    [JsonIgnore] public string BehaviorBadge => $"{Behavior.ToUpperInvariant()} · {Format.ToUpperInvariant()}";
    [JsonIgnore] public string StatusText => Loaded ? "● 已缓存生效" : "○ 待同步";
    [JsonIgnore] public string UrlDisplay => string.IsNullOrEmpty(Url) ? "内置本地规则集" : Url;
}

public sealed class NodeProviderRefDto
{
    [JsonPropertyName("key")] public string Key { get; set; } = "";
    [JsonPropertyName("url")] public string Url { get; set; } = "";
    [JsonPropertyName("intervalSeconds")] public uint IntervalSeconds { get; set; } = 3600;
    [JsonPropertyName("nodeCount")] public int NodeCount { get; set; }
    [JsonPropertyName("loaded")] public bool Loaded { get; set; }

    [JsonIgnore] public string StatusText => Loaded ? $"● 已同步 ({NodeCount} 节点)" : "○ 待拉取";
}

public sealed class ParsedRuleItemDto
{
    [JsonPropertyName("index")] public int Index { get; set; }
    [JsonPropertyName("type")] public string Type { get; set; } = "";
    [JsonPropertyName("pattern")] public string Pattern { get; set; } = "";
    [JsonPropertyName("policy")] public string Policy { get; set; } = "";
    [JsonPropertyName("noResolve")] public bool NoResolve { get; set; }

    [JsonIgnore] public string IndexText => $"#{Index}";
    [JsonIgnore] public string PatternDisplay => NoResolve ? $"{Pattern}  (no-resolve)" : Pattern;
}

public sealed class ActiveDnsConfigDto
{
    [JsonPropertyName("fakeIpEnabled")] public bool FakeIpEnabled { get; set; } = true;
    [JsonPropertyName("ipv6Enabled")] public bool Ipv6Enabled { get; set; }
    [JsonPropertyName("nameservers")] public List<string> Nameservers { get; set; } = [];
    [JsonPropertyName("encryptedUpstreams")] public List<string> EncryptedUpstreams { get; set; } = [];
}

public sealed class RulesSnapshotDto
{
    [JsonPropertyName("finalPolicy")] public string FinalPolicy { get; set; } = "DIRECT";
    [JsonPropertyName("baseRuleCount")] public int BaseRuleCount { get; set; }
    [JsonPropertyName("expandedRuleCount")] public int ExpandedRuleCount { get; set; }
    [JsonPropertyName("dns")] public ActiveDnsConfigDto Dns { get; set; } = new();
    [JsonPropertyName("rules")] public List<ParsedRuleItemDto> Rules { get; set; } = [];
}

public sealed class DiagnosticStageDto
{
    [JsonPropertyName("stage")] public int Stage { get; set; }
    [JsonPropertyName("name")] public string Name { get; set; } = "";
    [JsonPropertyName("status")] public string Status { get; set; } = "";
    [JsonPropertyName("p50Ms")] public double P50Ms { get; set; }
    [JsonPropertyName("p95Ms")] public double P95Ms { get; set; }
    [JsonPropertyName("queries")] public ulong Queries { get; set; }
    [JsonPropertyName("fakeIpHits")] public ulong FakeIpHits { get; set; }
    [JsonPropertyName("selfTestUs")] public long SelfTestUs { get; set; }
    [JsonPropertyName("httpPort")] public ushort HttpPort { get; set; }
    [JsonPropertyName("socksPort")] public ushort SocksPort { get; set; }
}

public sealed class DiagnosticsReportDto
{
    [JsonPropertyName("ok")] public bool Ok { get; set; }
    [JsonPropertyName("stages")] public List<DiagnosticStageDto> Stages { get; set; } = [];
}

public sealed class SafeEngineHandle : SafeHandleZeroOrMinusOneIsInvalid
{
    public SafeEngineHandle() : base(ownsHandle: true)
    {
        SetHandle(HajimiNativeMethods.EngineCreate());
    }

    protected override bool ReleaseHandle()
    {
        HajimiNativeMethods.EngineDestroy(handle);
        return true;
    }
}

public sealed class HajimiEngineClient : IDisposable
{
    private readonly SafeEngineHandle _handle = new();
    private readonly string _dataDir;

    public HajimiEngineClient(string dataDirectory)
    {
        if (_handle.IsInvalid)
            throw new InvalidOperationException("Failed to initialize HajimiEngine.dll");
        _dataDir = dataDirectory;
        Directory.CreateDirectory(_dataDir);
    }

    public string DataDirectory => _dataDir;

    public static string EngineVersion =>
        Marshal.PtrToStringUTF8(HajimiNativeMethods.EngineVersionPtr()) ?? "0.2.2";

    public unsafe void LoadProfileText(string content)
    {
        string normalized = NormalizeLineEndings(content);
        byte[] utf8 = Encoding.UTF8.GetBytes(normalized);
        byte[] err = new byte[512];
        fixed (byte* pText = utf8)
        fixed (byte* pErr = err)
        {
            byte dummy = 0;
            byte* pBuf = utf8.Length > 0 ? pText : &dummy;
            int rc = HajimiNativeMethods.EngineLoadProfileText(
                _handle.DangerousGetHandle(), pBuf, (nuint)utf8.Length, pErr, (nuint)err.Length);
            if (rc != 0)
                throw new InvalidOperationException(DecodeNullTerminatedUtf8(err));
        }
    }

    public unsafe void LoadProfileFile(string filePath)
    {
        byte[] pathBytes = NullTerminatedUtf8(filePath);
        byte[] err = new byte[512];
        fixed (byte* pPath = pathBytes)
        fixed (byte* pErr = err)
        {
            int rc = HajimiNativeMethods.EngineLoadProfileFile(
                _handle.DangerousGetHandle(), pPath, pErr, (nuint)err.Length);
            if (rc != 0)
                throw new InvalidOperationException(DecodeNullTerminatedUtf8(err));
        }
    }

    public unsafe void StartListeners(ushort httpPort = 7890, ushort socksPort = 7891,
                                      ushort controllerPort = 9090, string controllerKey = "")
    {
        byte[] hostBytes = NullTerminatedUtf8("127.0.0.1");
        byte[] keyBytes = NullTerminatedUtf8(controllerKey);
        byte[] err = new byte[512];

        fixed (byte* pHost = hostBytes)
        fixed (byte* pKey = keyBytes)
        fixed (byte* pErr = err)
        {
            var cfg = new NativeListenerConfig
            {
                BindHostUtf8 = pHost,
                HttpPort = httpPort,
                SocksPort = socksPort,
                ControllerPort = controllerPort,
                DnsListenPort = 0,
                ControllerKeyUtf8 = string.IsNullOrEmpty(controllerKey) ? null : pKey,
                OutboundIfNameUtf8 = null
            };
            int rc = HajimiNativeMethods.EngineStart(
                _handle.DangerousGetHandle(), &cfg, pErr, (nuint)err.Length);
            if (rc != 0)
                throw new InvalidOperationException(DecodeNullTerminatedUtf8(err));
        }
    }

    public void StopListeners() => HajimiNativeMethods.EngineStop(_handle.DangerousGetHandle());

    public ushort BoundHttpPort => HajimiNativeMethods.BoundHttpPort(_handle.DangerousGetHandle());
    public ushort BoundSocksPort => HajimiNativeMethods.BoundSocksPort(_handle.DangerousGetHandle());

    public void SetMode(OutboundRoutingMode mode) =>
        HajimiNativeMethods.SetOutboundMode(_handle.DangerousGetHandle(), (int)mode);

    public OutboundRoutingMode GetMode() =>
        (OutboundRoutingMode)HajimiNativeMethods.GetOutboundMode(_handle.DangerousGetHandle());

    public unsafe bool SelectPolicy(string groupName, string memberName)
    {
        byte[] g = NullTerminatedUtf8(groupName);
        byte[] m = NullTerminatedUtf8(memberName);
        fixed (byte* pg = g)
        fixed (byte* pm = m)
        {
            return HajimiNativeMethods.SelectPolicyGroup(_handle.DangerousGetHandle(), pg, pm) == 0;
        }
    }

    public unsafe bool SetGlobalNode(string nodeName)
    {
        byte[] n = NullTerminatedUtf8(nodeName);
        fixed (byte* pn = n)
        {
            return HajimiNativeMethods.SetGlobalNode(_handle.DangerousGetHandle(), pn) == 0;
        }
    }

    public unsafe string GetGlobalNode()
    {
        byte[] outBuf = new byte[256];
        fixed (byte* pout = outBuf)
        {
            int rc = HajimiNativeMethods.GetGlobalNode(_handle.DangerousGetHandle(), pout, (nuint)outBuf.Length);
            return rc == 0 ? DecodeNullTerminatedUtf8(outBuf) : "DIRECT";
        }
    }

    public unsafe string EvaluateRoute(string host, ushort port = 443, string proto = "TCP", string processName = "")
    {
        byte[] h = NullTerminatedUtf8(host);
        byte[] pr = NullTerminatedUtf8(proto);
        byte[] pc = NullTerminatedUtf8(processName);
        byte[] outBuf = new byte[256];
        fixed (byte* ph = h)
        fixed (byte* ppr = pr)
        fixed (byte* ppc = pc)
        fixed (byte* pout = outBuf)
        {
            int rc = HajimiNativeMethods.EvaluateRoute(
                _handle.DangerousGetHandle(), ph, port, ppr, ppc, pout, (nuint)outBuf.Length);
            return rc == 0 ? DecodeNullTerminatedUtf8(outBuf) : "DIRECT";
        }
    }

    public unsafe int ProbeNodeLatencyMs(string nodeName, uint timeoutMs = 3000)
    {
        byte[] n = NullTerminatedUtf8(nodeName);
        fixed (byte* pn = n)
        {
            return HajimiNativeMethods.ProbeNodeLatencyMs(_handle.DangerousGetHandle(), pn, timeoutMs);
        }
    }

    public int ProbeAllNodes(uint timeoutMs = 2500) =>
        HajimiNativeMethods.ProbeAllNodes(_handle.DangerousGetHandle(), timeoutMs);

    public List<RuleSetRefDto> GetRuleSets()
    {
        IntPtr ptr = HajimiNativeMethods.GetRuleSetsJson(_handle.DangerousGetHandle());
        if (ptr == IntPtr.Zero) return [];
        try
        {
            string json = Marshal.PtrToStringUTF8(ptr) ?? "[]";
            return JsonSerializer.Deserialize<List<RuleSetRefDto>>(json) ?? [];
        }
        finally
        {
            HajimiNativeMethods.FreeEngineString(ptr);
        }
    }

    public unsafe void UpdateRuleSet(string keyOrUrl, string content)
    {
        byte[] k = NullTerminatedUtf8(keyOrUrl);
        byte[] c = Encoding.UTF8.GetBytes(NormalizeLineEndings(content));
        fixed (byte* pk = k)
        fixed (byte* pc = c)
        {
            byte dummy = 0;
            byte* pContent = c.Length > 0 ? pc : &dummy;
            _ = HajimiNativeMethods.UpdateRuleSet(
                _handle.DangerousGetHandle(), pk, pContent, (nuint)c.Length);
        }
    }

    public List<NodeProviderRefDto> GetNodeProviders()
    {
        IntPtr ptr = HajimiNativeMethods.GetNodeProvidersJson(_handle.DangerousGetHandle());
        if (ptr == IntPtr.Zero) return [];
        try
        {
            string json = Marshal.PtrToStringUTF8(ptr) ?? "[]";
            return JsonSerializer.Deserialize<List<NodeProviderRefDto>>(json) ?? [];
        }
        finally
        {
            HajimiNativeMethods.FreeEngineString(ptr);
        }
    }

    public unsafe void UpdateNodeProvider(string keyOrUrl, string content)
    {
        byte[] k = NullTerminatedUtf8(keyOrUrl);
        byte[] c = Encoding.UTF8.GetBytes(NormalizeLineEndings(content));
        fixed (byte* pk = k)
        fixed (byte* pc = c)
        {
            byte dummy = 0;
            byte* pContent = c.Length > 0 ? pc : &dummy;
            _ = HajimiNativeMethods.UpdateNodeProvider(
                _handle.DangerousGetHandle(), pk, pContent, (nuint)c.Length);
        }
    }

    public RulesSnapshotDto GetRulesSnapshot()
    {
        IntPtr ptr = HajimiNativeMethods.GetRulesJson(_handle.DangerousGetHandle());
        if (ptr == IntPtr.Zero) return new RulesSnapshotDto();
        try
        {
            string json = Marshal.PtrToStringUTF8(ptr) ?? "{}";
            return JsonSerializer.Deserialize<RulesSnapshotDto>(json) ?? new RulesSnapshotDto();
        }
        finally
        {
            HajimiNativeMethods.FreeEngineString(ptr);
        }
    }

    private static string NormalizeLineEndings(string text)
    {
        if (string.IsNullOrEmpty(text)) return string.Empty;
        if (text[0] == '\uFEFF') text = text[1..];
        return text.Replace("\r\n", "\n").Replace('\r', '\n');
    }

    public unsafe void NotifyNetworkChange(string? interfaceAlias = null)
    {
        byte[] b = NullTerminatedUtf8(interfaceAlias ?? "");
        fixed (byte* pb = b)
        {
            HajimiNativeMethods.NotifyNetworkChange(
                _handle.DangerousGetHandle(), string.IsNullOrEmpty(interfaceAlias) ? null : pb);
        }
    }

    public void FlushDnsAndFakeIp()
    {
        HajimiNativeMethods.FlushDnsCache(_handle.DangerousGetHandle());
        HajimiNativeMethods.FlushFakeIp(_handle.DangerousGetHandle());
    }

    public bool AttachSharedMemoryTunnel(IntPtr shmView, nuint rxEvent, nuint txEvent) =>
        HajimiNativeMethods.AttachShmTunnel(_handle.DangerousGetHandle(), shmView, rxEvent, txEvent, 0u) == 0;

    public void DetachSharedMemoryTunnel() =>
        HajimiNativeMethods.DetachTunnel(_handle.DangerousGetHandle());

    public EngineStatusSnapshot GetStatusSnapshot()
    {
        IntPtr ptr = HajimiNativeMethods.GetStatusJson(_handle.DangerousGetHandle());
        if (ptr == IntPtr.Zero) return new EngineStatusSnapshot();
        try
        {
            string json = Marshal.PtrToStringUTF8(ptr) ?? "{}";
            return JsonSerializer.Deserialize<EngineStatusSnapshot>(json) ?? new EngineStatusSnapshot();
        }
        finally
        {
            HajimiNativeMethods.FreeEngineString(ptr);
        }
    }

    public List<ActiveConnectionDto> GetActiveConnections()
    {
        IntPtr ptr = HajimiNativeMethods.GetConnectionsJson(_handle.DangerousGetHandle());
        if (ptr == IntPtr.Zero) return [];
        try
        {
            string json = Marshal.PtrToStringUTF8(ptr) ?? "[]";
            return JsonSerializer.Deserialize<List<ActiveConnectionDto>>(json) ?? [];
        }
        finally
        {
            HajimiNativeMethods.FreeEngineString(ptr);
        }
    }

    public int CloseConnection(ulong connectionId = 0) =>
        HajimiNativeMethods.CloseConnection(_handle.DangerousGetHandle(), connectionId);

    public EngineLogBatchDto GetLogsSince(ulong sinceSeq)
    {
        IntPtr ptr = HajimiNativeMethods.GetLogsJson(_handle.DangerousGetHandle(), sinceSeq);
        if (ptr == IntPtr.Zero) return new EngineLogBatchDto { NextSeq = sinceSeq };
        try
        {
            string json = Marshal.PtrToStringUTF8(ptr) ?? "{}";
            return JsonSerializer.Deserialize<EngineLogBatchDto>(json) ?? new EngineLogBatchDto { NextSeq = sinceSeq };
        }
        finally
        {
            HajimiNativeMethods.FreeEngineString(ptr);
        }
    }

    public DiagnosticsReportDto RunDiagnostics()
    {
        IntPtr ptr = HajimiNativeMethods.RunDiagnosticsJson(_handle.DangerousGetHandle());
        if (ptr == IntPtr.Zero) return new DiagnosticsReportDto();
        try
        {
            string json = Marshal.PtrToStringUTF8(ptr) ?? "{}";
            return JsonSerializer.Deserialize<DiagnosticsReportDto>(json) ?? new DiagnosticsReportDto();
        }
        finally
        {
            HajimiNativeMethods.FreeEngineString(ptr);
        }
    }

    public unsafe void EnableSystemProxy(ushort port)
    {
        byte[] snap = NullTerminatedUtf8(_dataDir);
        byte[] host = NullTerminatedUtf8("127.0.0.1");
        byte[] bypass = NullTerminatedUtf8("localhost;127.*;10.*;172.16.*;192.168.*;<local>");
        byte[] err = new byte[512];
        fixed (byte* pSnap = snap)
        fixed (byte* pHost = host)
        fixed (byte* pBp = bypass)
        fixed (byte* pErr = err)
        {
            int rc = HajimiNativeMethods.WinSysProxyEnable(pSnap, pHost, port, pBp, pErr, (nuint)err.Length);
            if (rc != 0)
                throw new InvalidOperationException(DecodeNullTerminatedUtf8(err));
        }
    }

    public unsafe bool DisableSystemProxy(out string warningMessage)
    {
        warningMessage = "";
        byte[] snap = NullTerminatedUtf8(_dataDir);
        byte[] err = new byte[512];
        fixed (byte* pSnap = snap)
        fixed (byte* pErr = err)
        {
            int rc = HajimiNativeMethods.WinSysProxyDisable(pSnap, pErr, (nuint)err.Length);
            if (rc != 0)
            {
                warningMessage = DecodeNullTerminatedUtf8(err);
                return false;
            }
            return true;
        }
    }

    public unsafe bool IsSystemProxyOwned()
    {
        byte[] snap = NullTerminatedUtf8(_dataDir);
        fixed (byte* pSnap = snap)
        {
            return HajimiNativeMethods.WinSysProxyIsOwned(pSnap) == 1;
        }
    }

    public void Dispose()
    {
        if (!_handle.IsInvalid)
        {
            StopListeners();
            _handle.Dispose();
        }
    }

    private static byte[] NullTerminatedUtf8(string s)
    {
        int count = Encoding.UTF8.GetByteCount(s);
        byte[] buf = new byte[count + 1];
        Encoding.UTF8.GetBytes(s, 0, s.Length, buf, 0);
        return buf;
    }

    private static string DecodeNullTerminatedUtf8(byte[] buf)
    {
        int len = Array.IndexOf(buf, (byte)0);
        if (len < 0) len = buf.Length;
        return Encoding.UTF8.GetString(buf, 0, len);
    }
}
