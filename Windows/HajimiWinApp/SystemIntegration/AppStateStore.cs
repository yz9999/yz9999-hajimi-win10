using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using HajimiWinApp.Interop;

namespace HajimiWinApp.SystemIntegration;

public sealed class ManagedProfileEntry
{
    [JsonPropertyName("id")] public string Id { get; set; } = Guid.NewGuid().ToString("N")[..12];
    [JsonPropertyName("name")] public string Name { get; set; } = "";
    [JsonPropertyName("isLocalFile")] public bool IsLocalFile { get; set; }
    [JsonPropertyName("source")] public string Source { get; set; } = "";
    [JsonPropertyName("nodeCount")] public int NodeCount { get; set; }
    [JsonPropertyName("groupCount")] public int GroupCount { get; set; }
    [JsonPropertyName("updatedAt")] public string UpdatedAt { get; set; } = "";

    [JsonIgnore] public bool IsActive { get; set; }
    [JsonIgnore] public string ActiveBadge => IsActive ? "● 正在使用" : "○ 备用";
    [JsonIgnore] public string MetaSummary => IsLocalFile
        ? $"本地配置 · {NodeCount} 节点 · {GroupCount} 策略组 · 导入于 {UpdatedAt}"
        : $"{NodeCount} 节点 · {GroupCount} 策略组 · 更新于 {UpdatedAt}";
}

public sealed class PersistedUserSettings
{
    [JsonPropertyName("outboundMode")] public OutboundRoutingMode OutboundMode { get; set; } = OutboundRoutingMode.Rule;
    [JsonPropertyName("activeThemeId")] public string ActiveThemeId { get; set; } = "";
    [JsonPropertyName("subscriptionUrl")] public string SubscriptionUrl { get; set; } = "";
    [JsonPropertyName("lastSubSyncText")] public string LastSubSyncText { get; set; } = "";
    [JsonPropertyName("activeProfileEntryId")] public string ActiveProfileEntryId { get; set; } = "";
    [JsonPropertyName("managedProfiles")] public List<ManagedProfileEntry> ManagedProfiles { get; set; } = [];
    [JsonPropertyName("autoRefreshHours")] public int AutoRefreshHours { get; set; } = 6;
    [JsonPropertyName("systemProxyEnabled")] public bool SystemProxyEnabled { get; set; }
    [JsonPropertyName("closeToTray")] public bool CloseToTray { get; set; } = true;
    [JsonPropertyName("minimizeToTray")] public bool MinimizeToTray { get; set; } = true;
    [JsonPropertyName("httpPort")] public ushort HttpPort { get; set; } = 7890;
    [JsonPropertyName("socksPort")] public ushort SocksPort { get; set; } = 7891;
    [JsonPropertyName("controllerPort")] public ushort ControllerPort { get; set; } = 9090;
    [JsonPropertyName("globalSelectedNode")] public string GlobalSelectedNode { get; set; } = "__AUTO_FASTEST__";
    [JsonPropertyName("selectedPolicies")] public Dictionary<string, string> SelectedPolicies { get; set; } = [];
}

/// Atomic disk persistence for managed subscriptions, imported local profiles, user preferences,
/// cached `proxy-providers`, and cached remote `RULE-SET` / `GEOSITE` / `GEOIP` files.
public sealed class AppStateStore
{
    private static readonly JsonSerializerOptions JsonOpts = new() { WriteIndented = true };

    private readonly string _dataDir;
    private readonly string _settingsPath;
    private readonly string _activeProfilePath;
    private readonly string _profilesDir;
    private readonly string _ruleSetsDir;
    private readonly string _providersDir;
    private readonly object _ioLock = new();

    public PersistedUserSettings Settings { get; private set; } = new();

    public AppStateStore(string dataDirectory)
    {
        _dataDir = dataDirectory;
        _settingsPath = Path.Combine(_dataDir, "settings.json");
        _activeProfilePath = Path.Combine(_dataDir, "active-profile.conf");
        _profilesDir = Path.Combine(_dataDir, "profiles");
        _ruleSetsDir = Path.Combine(_dataDir, "rulesets");
        _providersDir = Path.Combine(_dataDir, "providers");

        Directory.CreateDirectory(_dataDir);
        Directory.CreateDirectory(_profilesDir);
        Directory.CreateDirectory(_ruleSetsDir);
        Directory.CreateDirectory(_providersDir);
        LoadSettings();
        MigrateLegacySubscriptionIfNeeded();
    }

    public void LoadSettings()
    {
        lock (_ioLock)
        {
            if (!File.Exists(_settingsPath)) return;
            try
            {
                string raw = File.ReadAllText(_settingsPath, Encoding.UTF8);
                Settings = JsonSerializer.Deserialize<PersistedUserSettings>(raw) ?? new PersistedUserSettings();
            }
            catch
            {
                Settings = new PersistedUserSettings();
            }
        }
    }

    public void SaveSettings()
    {
        lock (_ioLock)
        {
            try
            {
                string json = JsonSerializer.Serialize(Settings, JsonOpts);
                WriteFileAtomic(_settingsPath, json);
            }
            catch
            {
                // Ignore transient disk lock errors
            }
        }
    }

    private void MigrateLegacySubscriptionIfNeeded()
    {
        lock (_ioLock)
        {
            if (Settings.ManagedProfiles.Count > 0 || string.IsNullOrWhiteSpace(Settings.SubscriptionUrl))
                return;

            string? saved = ReadSavedProfileText();
            if (string.IsNullOrWhiteSpace(saved)) return;

            string hostLabel = Uri.TryCreate(Settings.SubscriptionUrl, UriKind.Absolute, out Uri? u)
                ? u.Host
                : "默认远程订阅";
            var migrated = new ManagedProfileEntry
            {
                Id = HashKey(Settings.SubscriptionUrl)[..12],
                Name = hostLabel,
                IsLocalFile = false,
                Source = Settings.SubscriptionUrl,
                UpdatedAt = DateTime.Now.ToString("yyyy-MM-dd HH:mm")
            };
            WriteFileAtomic(GetManagedProfilePath(migrated.Id), saved);
            Settings.ManagedProfiles.Add(migrated);
            Settings.ActiveProfileEntryId = migrated.Id;
            SaveSettings();
        }
    }

    public IReadOnlyList<ManagedProfileEntry> GetRemoteSubscriptions()
    {
        lock (_ioLock)
        {
            foreach (var p in Settings.ManagedProfiles)
                p.IsActive = p.Id == Settings.ActiveProfileEntryId;
            return Settings.ManagedProfiles.Where(x => !x.IsLocalFile).ToList();
        }
    }

    public IReadOnlyList<ManagedProfileEntry> GetLocalImportedProfiles()
    {
        lock (_ioLock)
        {
            foreach (var p in Settings.ManagedProfiles)
                p.IsActive = p.Id == Settings.ActiveProfileEntryId;
            return Settings.ManagedProfiles.Where(x => x.IsLocalFile).ToList();
        }
    }

    public ManagedProfileEntry? GetActiveManagedProfile()
    {
        lock (_ioLock)
        {
            return Settings.ManagedProfiles.FirstOrDefault(x => x.Id == Settings.ActiveProfileEntryId);
        }
    }

    public ManagedProfileEntry AddOrUpdateRemoteSubscription(
        string? customName,
        string url,
        string content,
        int nodeCount,
        int groupCount,
        bool setActive = true)
    {
        lock (_ioLock)
        {
            string normalized = NormalizeNewlines(content);
            var existing = Settings.ManagedProfiles.FirstOrDefault(
                x => !x.IsLocalFile && string.Equals(x.Source, url, StringComparison.OrdinalIgnoreCase));

            if (existing == null)
            {
                string fallbackName = Uri.TryCreate(url, UriKind.Absolute, out Uri? u) ? u.Host : "远程订阅";
                existing = new ManagedProfileEntry
                {
                    Id = Guid.NewGuid().ToString("N")[..12],
                    Name = string.IsNullOrWhiteSpace(customName) ? fallbackName : customName.Trim(),
                    IsLocalFile = false,
                    Source = url.Trim()
                };
                Settings.ManagedProfiles.Insert(0, existing);
            }
            else if (!string.IsNullOrWhiteSpace(customName))
            {
                existing.Name = customName.Trim();
            }

            existing.NodeCount = nodeCount;
            existing.GroupCount = groupCount;
            existing.UpdatedAt = DateTime.Now.ToString("yyyy-MM-dd HH:mm");
            WriteFileAtomic(GetManagedProfilePath(existing.Id), normalized);

            if (setActive)
            {
                Settings.ActiveProfileEntryId = existing.Id;
                Settings.SubscriptionUrl = existing.Source;
                WriteFileAtomic(_activeProfilePath, normalized);
            }
            SaveSettings();
            return existing;
        }
    }

    public ManagedProfileEntry AddImportedLocalProfile(
        string originalFilePath,
        string content,
        int nodeCount,
        int groupCount,
        bool setActive = true)
    {
        lock (_ioLock)
        {
            string normalized = NormalizeNewlines(content);
            string fileName = Path.GetFileName(originalFilePath);
            if (string.IsNullOrWhiteSpace(fileName)) fileName = "local-profile.conf";

            var entry = Settings.ManagedProfiles.FirstOrDefault(
                x => x.IsLocalFile && string.Equals(x.Name, fileName, StringComparison.OrdinalIgnoreCase));

            if (entry == null)
            {
                entry = new ManagedProfileEntry
                {
                    Id = Guid.NewGuid().ToString("N")[..12],
                    Name = fileName,
                    IsLocalFile = true,
                    Source = originalFilePath
                };
                Settings.ManagedProfiles.Insert(0, entry);
            }

            entry.Source = originalFilePath;
            entry.NodeCount = nodeCount;
            entry.GroupCount = groupCount;
            entry.UpdatedAt = DateTime.Now.ToString("yyyy-MM-dd HH:mm");
            WriteFileAtomic(GetManagedProfilePath(entry.Id), normalized);

            if (setActive)
            {
                Settings.ActiveProfileEntryId = entry.Id;
                WriteFileAtomic(_activeProfilePath, normalized);
            }
            SaveSettings();
            return entry;
        }
    }

    public string? ActivateManagedProfile(string entryId)
    {
        lock (_ioLock)
        {
            var entry = Settings.ManagedProfiles.FirstOrDefault(x => x.Id == entryId);
            if (entry == null) return null;
            string path = GetManagedProfilePath(entry.Id);
            if (!File.Exists(path)) return null;

            string content = NormalizeNewlines(File.ReadAllText(path, Encoding.UTF8));
            Settings.ActiveProfileEntryId = entry.Id;
            if (!entry.IsLocalFile) Settings.SubscriptionUrl = entry.Source;
            WriteFileAtomic(_activeProfilePath, content);
            SaveSettings();
            return content;
        }
    }

    public bool DeleteManagedProfile(string entryId, out ManagedProfileEntry? nextActiveEntry, out string? nextContent)
    {
        nextActiveEntry = null;
        nextContent = null;
        lock (_ioLock)
        {
            int idx = Settings.ManagedProfiles.FindIndex(x => x.Id == entryId);
            if (idx < 0) return false;

            var removed = Settings.ManagedProfiles[idx];
            Settings.ManagedProfiles.RemoveAt(idx);

            string filePath = GetManagedProfilePath(removed.Id);
            try { if (File.Exists(filePath)) File.Delete(filePath); } catch { }

            if (Settings.ActiveProfileEntryId == removed.Id)
            {
                var next = Settings.ManagedProfiles.FirstOrDefault();
                if (next != null)
                {
                    Settings.ActiveProfileEntryId = next.Id;
                    Settings.SubscriptionUrl = next.IsLocalFile ? "" : next.Source;
                    string nextPath = GetManagedProfilePath(next.Id);
                    if (File.Exists(nextPath))
                    {
                        nextContent = NormalizeNewlines(File.ReadAllText(nextPath, Encoding.UTF8));
                        WriteFileAtomic(_activeProfilePath, nextContent);
                    }
                    nextActiveEntry = next;
                }
                else
                {
                    Settings.ActiveProfileEntryId = "";
                    Settings.SubscriptionUrl = "";
                }
            }
            SaveSettings();
            return true;
        }
    }

    public string? ReadSavedProfileText()
    {
        lock (_ioLock)
        {
            if (!string.IsNullOrWhiteSpace(Settings.ActiveProfileEntryId))
            {
                string managedPath = GetManagedProfilePath(Settings.ActiveProfileEntryId);
                if (File.Exists(managedPath))
                {
                    try { return NormalizeNewlines(File.ReadAllText(managedPath, Encoding.UTF8)); } catch { }
                }
            }
            if (!File.Exists(_activeProfilePath)) return null;
            try
            {
                string raw = File.ReadAllText(_activeProfilePath, Encoding.UTF8);
                return NormalizeNewlines(raw);
            }
            catch
            {
                return null;
            }
        }
    }

    public void SaveActiveProfileText(string content, int? nodeCount = null, int? groupCount = null)
    {
        lock (_ioLock)
        {
            try
            {
                string norm = NormalizeNewlines(content);
                WriteFileAtomic(_activeProfilePath, norm);
                if (!string.IsNullOrWhiteSpace(Settings.ActiveProfileEntryId))
                {
                    var cur = Settings.ManagedProfiles.FirstOrDefault(x => x.Id == Settings.ActiveProfileEntryId);
                    if (cur != null)
                    {
                        WriteFileAtomic(GetManagedProfilePath(cur.Id), norm);
                        if (nodeCount.HasValue) cur.NodeCount = nodeCount.Value;
                        if (groupCount.HasValue) cur.GroupCount = groupCount.Value;
                        cur.UpdatedAt = DateTime.Now.ToString("yyyy-MM-dd HH:mm");
                        SaveSettings();
                    }
                }
            }
            catch
            {
                // Ignore transient disk lock errors
            }
        }
    }

    public static string NormalizeNewlines(string text)
    {
        if (string.IsNullOrEmpty(text)) return string.Empty;
        if (text[0] == '\uFEFF') text = text[1..];
        return text.Replace("\r\n", "\n").Replace('\r', '\n');
    }

    public void LoadCachedProvidersAndRuleSetsIntoEngine(HajimiEngineClient engine)
    {
        LoadCachedNodeProvidersIntoEngine(engine);
        LoadCachedRuleSetsIntoEngine(engine);
    }

    public void LoadCachedNodeProvidersIntoEngine(HajimiEngineClient engine)
    {
        var providers = engine.GetNodeProviders();
        foreach (var np in providers)
        {
            string cachePath = GetProviderCachePath(np.Key);
            if (!File.Exists(cachePath)) continue;
            try
            {
                string cached = NormalizeNewlines(File.ReadAllText(cachePath, Encoding.UTF8));
                if (!string.IsNullOrWhiteSpace(cached))
                {
                    engine.UpdateNodeProvider(np.Key, cached);
                }
            }
            catch { }
        }
    }

    public void LoadCachedRuleSetsIntoEngine(HajimiEngineClient engine)
    {
        var ruleSets = engine.GetRuleSets();
        foreach (var rs in ruleSets)
        {
            string cachePath = GetRuleSetCachePath(rs.Key);
            if (!File.Exists(cachePath)) continue;
            try
            {
                string cached = NormalizeNewlines(File.ReadAllText(cachePath, Encoding.UTF8));
                if (LooksLikeValidRuleList(cached))
                {
                    engine.UpdateRuleSet(rs.Key, cached);
                }
            }
            catch { }
        }
    }

    public static async Task<string?> DownloadTextSmartAsync(
        HajimiEngineClient engine,
        HttpClient directHttp,
        Uri uri,
        CancellationToken ct = default)
    {
        ushort proxyPort = engine.BoundHttpPort;
        bool canUseLocalProxy = proxyPort != 0 && engine.GetStatusSnapshot().NodeCount > 0;

        if (canUseLocalProxy)
        {
            try
            {
                using var handler = new HttpClientHandler
                {
                    Proxy = new WebProxy($"http://127.0.0.1:{proxyPort}"),
                    UseProxy = true
                };
                using var proxiedClient = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(10) };
                proxiedClient.DefaultRequestHeaders.UserAgent.ParseAdd("ClashMetaForAndroid/2.10.1 mihomo/1.18.8 Hajimi/0.2");
                using var resp = await proxiedClient.GetAsync(uri, HttpCompletionOption.ResponseHeadersRead, ct);
                if (resp.IsSuccessStatusCode)
                {
                    byte[] bytes = await resp.Content.ReadAsByteArrayAsync(ct);
                    if (bytes.Length > 0 && bytes.Length <= 8 * 1024 * 1024 && !ContainsBinaryNulls(bytes))
                    {
                        return NormalizeNewlines(Encoding.UTF8.GetString(bytes));
                    }
                }
            }
            catch { }
        }

        try
        {
            using var req = new HttpRequestMessage(HttpMethod.Get, uri);
            req.Headers.UserAgent.ParseAdd("ClashMetaForAndroid/2.10.1 mihomo/1.18.8 Hajimi/0.2");
            using var resp = await directHttp.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, ct);
            if (!resp.IsSuccessStatusCode) return null;
            byte[] bytes = await resp.Content.ReadAsByteArrayAsync(ct);
            if (bytes.Length == 0 || bytes.Length > 8 * 1024 * 1024 || ContainsBinaryNulls(bytes))
                return null;
            return NormalizeNewlines(Encoding.UTF8.GetString(bytes));
        }
        catch
        {
            return null;
        }
    }

    public async Task<int> RefreshRemoteNodeProvidersAsync(
        HajimiEngineClient engine,
        HttpClient httpClient,
        CancellationToken ct = default)
    {
        var providers = engine.GetNodeProviders();
        if (providers.Count == 0) return 0;

        int updated = 0;
        using var gate = new SemaphoreSlim(4, 4);
        var tasks = providers.Select(async np =>
        {
            if (string.IsNullOrWhiteSpace(np.Url) || !Uri.TryCreate(np.Url, UriKind.Absolute, out Uri? uri))
                return;

            await gate.WaitAsync(ct);
            try
            {
                string? body = await DownloadTextSmartAsync(engine, httpClient, uri, ct);
                if (!string.IsNullOrWhiteSpace(body) && !LooksLikeHtmlPage(body))
                {
                    lock (_ioLock)
                    {
                        WriteFileAtomic(GetProviderCachePath(np.Key), body);
                    }
                    engine.UpdateNodeProvider(np.Key, body);
                    Interlocked.Increment(ref updated);
                }
            }
            finally
            {
                gate.Release();
            }
        });

        await Task.WhenAll(tasks);
        return updated;
    }

    public async Task<int> RefreshRemoteRuleSetsAsync(
        HajimiEngineClient engine,
        HttpClient httpClient,
        CancellationToken ct = default)
    {
        _ = await RefreshRemoteNodeProvidersAsync(engine, httpClient, ct);

        var ruleSets = engine.GetRuleSets();
        if (ruleSets.Count == 0) return 0;

        int updated = 0;
        using var gate = new SemaphoreSlim(6, 6);
        var tasks = ruleSets.Select(async rs =>
        {
            var candidateUris = BuildCandidateRuleSetUris(rs);
            if (candidateUris.Count == 0) return;

            await gate.WaitAsync(ct);
            try
            {
                foreach (var uri in candidateUris)
                {
                    string? content = await DownloadTextSmartAsync(engine, httpClient, uri, ct);
                    if (content != null && LooksLikeValidRuleList(content))
                    {
                        lock (_ioLock)
                        {
                            WriteFileAtomic(GetRuleSetCachePath(rs.Key), content);
                        }
                        engine.UpdateRuleSet(rs.Key, content);
                        Interlocked.Increment(ref updated);
                        break;
                    }
                }
            }
            finally
            {
                gate.Release();
            }
        });

        await Task.WhenAll(tasks);
        return updated;
    }

    private static List<Uri> BuildCandidateRuleSetUris(RuleSetRefDto rs)
    {
        var list = new List<Uri>();
        void AddIfValid(string raw)
        {
            if (Uri.TryCreate(raw, UriKind.Absolute, out Uri? u) &&
                (u.Scheme == Uri.UriSchemeHttps || u.Scheme == Uri.UriSchemeHttp) &&
                !list.Contains(u))
            {
                list.Add(u);
            }
        }

        if (string.Equals(rs.Key, "GEOIP:CN", StringComparison.OrdinalIgnoreCase))
        {
            AddIfValid("https://testingcf.jsdelivr.net/gh/Loyalsoldier/geoip@release/text/cn.txt");
            AddIfValid("https://fastly.jsdelivr.net/gh/Loyalsoldier/geoip@release/text/cn.txt");
            AddIfValid("https://raw.githubusercontent.com/Loyalsoldier/geoip/release/text/cn.txt");
            if (!string.IsNullOrWhiteSpace(rs.Url)) AddIfValid(rs.Url);
            return list;
        }

        if (rs.Key.StartsWith("GEOSITE:", StringComparison.OrdinalIgnoreCase))
        {
            string site = rs.Key["GEOSITE:".Length..].ToLowerInvariant();
            AddIfValid($"https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@meta/geo/geosite/{site}.list");
            AddIfValid($"https://fastly.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@meta/geo/geosite/{site}.list");
            AddIfValid($"https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/{site}.list");
            return list;
        }

        if (!string.IsNullOrWhiteSpace(rs.Url))
        {
            string u = rs.Url.Trim();
            if (u.EndsWith(".mrs", StringComparison.OrdinalIgnoreCase))
            {
                string stem = u[..^4];
                foreach (string cand in ExpandGithubMirrors(stem + ".list")) AddIfValid(cand);
                foreach (string cand in ExpandGithubMirrors(stem + ".yaml")) AddIfValid(cand);
            }
            else
            {
                foreach (string cand in ExpandGithubMirrors(u)) AddIfValid(cand);
            }
        }
        return list;
    }

    private static IEnumerable<string> ExpandGithubMirrors(string url)
    {
        const string rawPrefix = "https://raw.githubusercontent.com/";
        if (url.StartsWith(rawPrefix, StringComparison.OrdinalIgnoreCase))
        {
            string rest = url[rawPrefix.Length..];
            string[] segs = rest.Split('/', 4);
            if (segs.Length == 4)
            {
                string jsdPath = $"{segs[0]}/{segs[1]}@{segs[2]}/{segs[3]}";
                yield return $"https://testingcf.jsdelivr.net/gh/{jsdPath}";
                yield return $"https://fastly.jsdelivr.net/gh/{jsdPath}";
            }
        }
        yield return url;
    }

    private static bool ContainsBinaryNulls(byte[] bytes)
    {
        int checkLen = Math.Min(bytes.Length, 4096);
        int controlCount = 0;
        for (int i = 0; i < checkLen; i++)
        {
            byte b = bytes[i];
            if (b == 0) return true;
            if (b < 0x09 || (b > 0x0D && b < 0x20)) controlCount++;
        }
        return checkLen > 16 && controlCount * 20 > checkLen;
    }

    private static bool LooksLikeHtmlPage(string content)
    {
        string head = content.AsSpan().TrimStart().ToString();
        return head.StartsWith("<!DOCTYPE", StringComparison.OrdinalIgnoreCase) ||
               head.StartsWith("<html", StringComparison.OrdinalIgnoreCase);
    }

    public static bool LooksLikeValidRuleList(string content)
    {
        if (string.IsNullOrWhiteSpace(content)) return false;
        if (content.IndexOf('\0') >= 0) return false;
        if (LooksLikeHtmlPage(content)) return false;
        return true;
    }

    private string GetManagedProfilePath(string id) => Path.Combine(_profilesDir, $"{id}.conf");
    private string GetRuleSetCachePath(string key) => Path.Combine(_ruleSetsDir, $"{HashKey(key)}.ruleset");
    private string GetProviderCachePath(string key) => Path.Combine(_providersDir, $"{HashKey(key)}.provider");

    private static string HashKey(string key)
    {
        byte[] hash = SHA256.HashData(Encoding.UTF8.GetBytes(key));
        return Convert.ToHexString(hash)[..24].ToLowerInvariant();
    }

    private static void WriteFileAtomic(string targetPath, string content)
    {
        string tmp = targetPath + ".tmp";
        File.WriteAllText(tmp, content, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
        File.Move(tmp, targetPath, overwrite: true);
    }
}
