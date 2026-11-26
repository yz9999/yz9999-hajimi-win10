using System.Net.Http;
using System.Runtime.InteropServices;
using System.Text;
using HajimiWinApp.Controls;
using HajimiWinApp.Interop;
using HajimiWinApp.SystemIntegration;
using HajimiWinApp.Themes;
using Microsoft.UI;
using Microsoft.UI.Composition.SystemBackdrops;
using Microsoft.UI.Windowing;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Windows.Graphics;
using Windows.UI;
using WinRT.Interop;

namespace HajimiWinApp;

public sealed partial class MainWindow : Window
{
    static MainWindow()
    {
        Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct OPENFILENAMEW
    {
        public int lStructSize;
        public IntPtr hwndOwner;
        public IntPtr hInstance;
        public IntPtr lpstrFilter;
        public IntPtr lpstrCustomFilter;
        public int nMaxCustFilter;
        public int nFilterIndex;
        public IntPtr lpstrFile;
        public int nMaxFile;
        public IntPtr lpstrFileTitle;
        public int nMaxFileTitle;
        public IntPtr lpstrInitialDir;
        public IntPtr lpstrTitle;
        public int Flags;
        public short nFileOffset;
        public short nFileExtension;
        public IntPtr lpstrDefExt;
        public IntPtr lCustData;
        public IntPtr lpfnHook;
        public IntPtr lpTemplateName;
        public IntPtr pvReserved;
        public int dwReserved;
        public int FlagsEx;
    }

    [LibraryImport("comdlg32.dll", EntryPoint = "GetOpenFileNameW", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GetOpenFileNameW(ref OPENFILENAMEW ofn);

    private const string DefaultStarterProfile = """
        # Hajimi 默认初始配置（可在此直接编辑，或点击右上角「导入本地配置」加载 Surge .conf / Clash .yaml）
        [General]
        http-listen = 127.0.0.1:7890
        socks5-listen = 127.0.0.1:7891
        dns-server = 223.5.5.5, 119.29.29.29, 1.1.1.1
        encrypted-dns-server = https://1.1.1.1/dns-query, tls://1.1.1.1:853
        enhanced-mode = fake-ip
        ipv6 = false
        skip-proxy = localhost, 127.0.0.1, *.local, 10.*, 172.16.*, 192.168.*

        [Proxy]

        [Proxy Group]
        🚀 节点选择 = select, DIRECT

        [Rule]
        RULE-SET, LAN, DIRECT
        RULE-SET, SYSTEM, DIRECT
        GEOIP, CN, DIRECT
        FINAL, 🚀 节点选择
        """;

    private readonly HajimiEngineClient _engine;
    private readonly AppStateStore _stateStore;
    private readonly HajimiWinThemeEngine _themeEngine = new();
    private readonly HelperPipeClient _helperClient = new();
    private readonly TrayIconService _trayService = new();
    private TrayPopoverWindow? _trayPopover;
    private readonly NetworkPowerWatcher _networkWatcher;
    private readonly DispatcherTimer _telemetryTimer;
    private readonly DispatcherTimer _subAutoRefreshTimer;
    private static readonly HttpClient SubHttp = new() { Timeout = TimeSpan.FromSeconds(18) };

    private bool _suppressToggleEvents;
    private bool _explicitExitRequested;
    private bool _showingRawRulesEditor;
    private ulong _lastLogSeq;
    private readonly List<string> _logLines = new(260);
    private List<ActiveConnectionDto> _latestConnections = [];
    private List<ProxyNodeDto> _latestNodes = [];
    private List<ParsedRuleItemDto> _latestParsedRules = [];

    public MainWindow()
    {
        InitializeComponent();

        // Match macOS window proportions (1240 x 820) and activate immersive unified TitleBar
        ConfigureUnifiedWindowChrome();

        NavList.SelectedIndex = 0;

        if (MicaController.IsSupported())
        {
            SystemBackdrop = new MicaBackdrop();
        }

        string dataDir = Environment.GetEnvironmentVariable("HAJIMI_DATA_DIR")
            ?? System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Hajimi");

        _stateStore = new AppStateStore(dataDir);
        _engine = new HajimiEngineClient(dataDir);

        string? initNic = NetworkPowerWatcher.DetectPrimaryPhysicalNic(out _);
        if (!string.IsNullOrEmpty(initNic)) _engine.NotifyNetworkChange(initNic);
        EngineVersionLabel.Text = $"Core {HajimiEngineClient.EngineVersion}";

        // Load built-in 50 themes and restore user-selected theme
        int loadedThemes = _themeEngine.LoadBuiltInPack();
        ThemeGalleryList.ItemsSource = _themeEngine.Themes;
        if (loadedThemes > 0)
        {
            string targetTheme = !string.IsNullOrWhiteSpace(_stateStore.Settings.ActiveThemeId)
                ? _stateStore.Settings.ActiveThemeId
                : _themeEngine.Themes[0].Id;
            if (!_themeEngine.ApplyTheme(targetTheme, RootGrid, Application.Current.Resources))
            {
                _themeEngine.ApplyTheme(_themeEngine.Themes[0].Id, RootGrid, Application.Current.Resources);
            }
            SyncThemeVisualChrome(_themeEngine.ActiveTheme);
        }
        _themeEngine.ThemeChanged += t =>
        {
            SyncThemeVisualChrome(t);
            _stateStore.Settings.ActiveThemeId = t.Id;
            _stateStore.SaveSettings();
            RefreshPolicyGroupCards();
            UpdateRulesSegmentedStyle();
            ApplyRoutingMode(_stateStore.Settings.OutboundMode, persist: false);
        };

        UpdateRulesSegmentedStyle();

        // Start local HTTP/SOCKS5/Controller listeners BEFORE profile warmup so BoundHttpPort is live
        try
        {
            _engine.StartListeners(
                httpPort: _stateStore.Settings.HttpPort,
                socksPort: _stateStore.Settings.SocksPort,
                controllerPort: _stateStore.Settings.ControllerPort);
        }
        catch (Exception ex)
        {
            ShowBanner(InfoBarSeverity.Warning, $"默认监听端口绑定提示：{ex.Message}");
        }

        // Restore persisted profile (or seed clean starter profile on first run), cached providers/rulesets, and policy choices
        RestorePersistedEngineState();

        // Restore WinINet System Proxy if enabled in previous session
        _suppressToggleEvents = true;
        CloseToTrayCheck.IsChecked = _stateStore.Settings.CloseToTray;
        AutoStartCheck.IsChecked = TrayIconService.IsAutoStartEnabled();
        if (_stateStore.Settings.SystemProxyEnabled && _engine.BoundHttpPort != 0)
        {
            try
            {
                _engine.EnableSystemProxy(_engine.BoundHttpPort);
                SysProxyToggle.IsOn = true;
            }
            catch
            {
                SysProxyToggle.IsOn = false;
            }
        }
        _suppressToggleEvents = false;

        IntPtr hwnd = WindowNative.GetWindowHandle(this);
        _trayService.CurrentMode = _stateStore.Settings.OutboundMode;
        _trayService.IsSystemProxyEnabled = SysProxyToggle.IsOn;
        _trayService.MinimizeToTrayOnMinimize = _stateStore.Settings.CloseToTray;
        _trayService.ActiveProfileTitle = _stateStore.GetActiveManagedProfile()?.Name ?? "默认配置";
        _trayService.SnapshotProvider = () => _engine.GetStatusSnapshot();
        _trayService.TrayPopoverToggleRequested += () => DispatcherQueue.TryEnqueue(ToggleTrayPopoverCard);
        _trayService.PolicyGroupSelectionRequested += (grp, mem) => DispatcherQueue.TryEnqueue(() => SelectPolicyGroupFromTray(grp, mem));
        _trayService.GlobalNodeSelectionRequested += nodeName => DispatcherQueue.TryEnqueue(() => SelectGlobalNodeFromTray(nodeName));
        _trayService.MenuActionRequested += OnTrayMenuAction;
        _trayService.Initialize(hwnd);

        if (Environment.GetCommandLineArgs().Any(a => string.Equals(a, "--minimized", StringComparison.OrdinalIgnoreCase)))
        {
            DispatcherQueue.TryEnqueue(() => _trayService.HideMainWindow());
        }

        AppWindow.Closing += OnAppWindowClosing;

        _networkWatcher = new NetworkPowerWatcher(nicAlias =>
        {
            _engine.NotifyNetworkChange(nicAlias);
        });

        _telemetryTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(1) };
        _telemetryTimer.Tick += OnTelemetryTick;
        _telemetryTimer.Start();

        _subAutoRefreshTimer = new DispatcherTimer
        {
            Interval = TimeSpan.FromHours(Math.Max(1, _stateStore.Settings.AutoRefreshHours))
        };
        _subAutoRefreshTimer.Tick += async (_, _) => await SilentRefreshSubscriptionAndRuleSetsAsync();
        _subAutoRefreshTimer.Start();

        // Populate initial 5-stage diagnostic cards and run non-blocking background rule/provider warmup
        RenderDiagnosticsReport(_engine.RunDiagnostics());
        _ = BackgroundWarmupAsync();

        Closed += OnWindowClosed;
    }

    private void ConfigureUnifiedWindowChrome()
    {
        try
        {
            AppWindow.Resize(new SizeInt32(1250, 830));
            ExtendsContentIntoTitleBar = true;
            SetTitleBar(AppTitleBar);
            if (AppWindowTitleBar.IsCustomizationSupported())
            {
                var tb = AppWindow.TitleBar;
                tb.ExtendsContentIntoTitleBar = true;
                tb.ButtonBackgroundColor = Colors.Transparent;
                tb.ButtonInactiveBackgroundColor = Colors.Transparent;
            }
        }
        catch
        {
            // Graceful fallback on legacy desktop shells
        }
    }

    private void SyncThemeVisualChrome(HajimiThemeTokenSet theme)
    {
        var down = HajimiWinThemeEngine.ParseHexColor(theme.AccentHex, Color.FromArgb(255, 46, 209, 156));
        var up = HajimiWinThemeEngine.ParseHexColor(theme.UploadAccentHex, Color.FromArgb(255, 89, 176, 250));
        var sec = HajimiWinThemeEngine.ParseHexColor(theme.TextSecondaryHex, Color.FromArgb(255, 141, 163, 153));
        var pri = HajimiWinThemeEngine.ParseHexColor(theme.TextPrimaryHex, Color.FromArgb(255, 236, 253, 245));
        var elev = HajimiWinThemeEngine.ParseHexColor(theme.ElevatedPanelHex, Color.FromArgb(255, 32, 38, 41));
        WaveformChart.UpdatePalette(down, up, sec);

        if (ActiveThemeStatusText != null)
        {
            ActiveThemeStatusText.Text =
                $"当前启用：{theme.Code} {theme.Name}（{theme.Category} · {theme.LayoutStyle}）— 共 {_themeEngine.Themes.Count} 款双端同源主题";
        }

        try
        {
            if (AppWindowTitleBar.IsCustomizationSupported())
            {
                var tb = AppWindow.TitleBar;
                tb.ButtonForegroundColor = pri;
                tb.ButtonHoverForegroundColor = pri;
                tb.ButtonHoverBackgroundColor = elev;
                tb.ButtonPressedBackgroundColor = down;
                tb.ButtonInactiveForegroundColor = sec;
            }
        }
        catch
        {
            // Ignore caption customization errors
        }
    }

    private static Brush ResBrush(string key, Color fallback)
    {
        if (Application.Current.Resources.TryGetValue(key, out object? obj) && obj is Brush b)
            return b;
        return new SolidColorBrush(fallback);
    }

    private void RestorePersistedEngineState()
    {
        SubUrlInput.Text = _stateStore.Settings.SubscriptionUrl;
        if (!string.IsNullOrWhiteSpace(_stateStore.Settings.LastSubSyncText))
        {
            SubSyncStatusLabel.Text = _stateStore.Settings.LastSubSyncText;
        }

        string? savedProfile = _stateStore.ReadSavedProfileText();
        string effectiveProfile = string.IsNullOrWhiteSpace(savedProfile) ? DefaultStarterProfile : savedProfile;
        ProfileEditorBox.Text = effectiveProfile;

        try
        {
            _engine.LoadProfileText(effectiveProfile);
            if (string.IsNullOrWhiteSpace(savedProfile))
            {
                _stateStore.SaveActiveProfileText(effectiveProfile);
            }
            _stateStore.LoadCachedProvidersAndRuleSetsIntoEngine(_engine);
            RestoreSavedPolicySelections();
        }
        catch (Exception ex)
        {
            ShowBanner(InfoBarSeverity.Warning, $"恢复本地保存配置时提示：{ex.Message}");
        }

        ApplyRoutingMode(_stateStore.Settings.OutboundMode, persist: false);
        RefreshAllProfileViews();
    }

    private void RestoreSavedPolicySelections()
    {
        if (!string.IsNullOrWhiteSpace(_stateStore.Settings.GlobalSelectedNode))
        {
            _engine.SetGlobalNode(_stateStore.Settings.GlobalSelectedNode);
        }
        foreach (var kv in _stateStore.Settings.SelectedPolicies)
        {
            _engine.SelectPolicy(kv.Key, kv.Value);
        }
    }

    private async Task BackgroundWarmupAsync()
    {
        try
        {
            int updatedRs = await _stateStore.RefreshRemoteRuleSetsAsync(_engine, SubHttp);
            if (updatedRs > 0)
            {
                DispatcherQueue.TryEnqueue(() =>
                {
                    RestoreSavedPolicySelections();
                    RefreshAllProfileViews();
                });
            }
            var snap = _engine.GetStatusSnapshot();
            if (snap.NodeCount > 0)
            {
                await Task.Run(() => _engine.ProbeAllNodes(2500));
                DispatcherQueue.TryEnqueue(RefreshAllProfileViews);
            }
        }
        catch
        {
            // Ignore background warmup network errors
        }
    }

    private async Task SilentRefreshSubscriptionAndRuleSetsAsync()
    {
        string url = _stateStore.Settings.SubscriptionUrl;
        if (!string.IsNullOrWhiteSpace(url) && Uri.TryCreate(url, UriKind.Absolute, out Uri? uri) &&
            (uri.Scheme == Uri.UriSchemeHttps || uri.Scheme == Uri.UriSchemeHttp))
        {
            try
            {
                string? raw = await AppStateStore.DownloadTextSmartAsync(_engine, SubHttp, uri);
                if (!string.IsNullOrWhiteSpace(raw))
                {
                    string text = NormalizeAndMaybeDecodeProfileText(raw);
                    if (!string.IsNullOrWhiteSpace(text))
                    {
                        _engine.LoadProfileText(text);
                        _stateStore.SaveActiveProfileText(text);
                        _stateStore.LoadCachedProvidersAndRuleSetsIntoEngine(_engine);
                        RestoreSavedPolicySelections();
                        ProfileEditorBox.Text = text;
                        string syncNote = $"上次自动同步：{DateTime.Now:yyyy-MM-dd HH:mm:ss}";
                        SubSyncStatusLabel.Text = syncNote;
                        _stateStore.Settings.LastSubSyncText = syncNote;
                        _stateStore.SaveSettings();
                    }
                }
            }
            catch
            {
                // Keep previous active profile on transient network failure
            }
        }
        await _stateStore.RefreshRemoteRuleSetsAsync(_engine, SubHttp);
        RestoreSavedPolicySelections();
        RefreshAllProfileViews();
    }

    private static string FormatTotalBytes(ulong b)
    {
        if (b < 1024) return $"{b} B";
        if (b < 1024 * 1024) return $"{b / 1024.0:F1} KB";
        if (b < 1024UL * 1024 * 1024) return $"{b / (1024.0 * 1024.0):F1} MB";
        return $"{b / (1024.0 * 1024.0 * 1024.0):F2} GB";
    }

    private void OnTelemetryTick(object? sender, object e)
    {
        var snap = _engine.GetStatusSnapshot();
        string downStr = TrafficWaveformCanvas.FormatRate(snap.DownloadBps);
        string upStr = TrafficWaveformCanvas.FormatRate(snap.UploadBps);

        DownSpeedText.Text = downStr;
        UpSpeedText.Text = upStr;
        TotalDownText.Text = $"累计下行 {FormatTotalBytes(snap.DownloadedBytes)}";
        TotalUpText.Text = $"累计上行 {FormatTotalBytes(snap.UploadedBytes)}";
        ActiveConnText.Text = snap.ActiveUdpSessions > 0
            ? $"{snap.ActiveConnections} (UDP:{snap.ActiveUdpSessions})"
            : snap.ActiveConnections.ToString();
        TotalConnSubText.Text = $"累计接管 {snap.TotalConnections} 次会话";
        DnsHitText.Text = $"{snap.FakeIpHits} / {snap.DnsQueries}";
        WaveformChart.PushSample(snap.DownloadBps, snap.UploadBps);

        ushort hp = snap.HttpPort > 0 ? snap.HttpPort : _stateStore.Settings.HttpPort;
        ushort sp = snap.SocksPort > 0 ? snap.SocksPort : _stateStore.Settings.SocksPort;
        OverviewHttpEndpointText.Text = snap.Running ? $"127.0.0.1:{hp}" : "未监听";
        OverviewSocksEndpointText.Text = snap.Running ? $"127.0.0.1:{sp}" : "未监听";
        SidebarRunBadgeText.Text = snap.Running ? "运行中" : "待机";
        TitleBarStatusText.Text = _helperClient.IsEnhancedModeActive
            ? $"Hajimi Core {snap.Version}  ·  Wintun 增强模式已接管  ·  ↓ {downStr}  ↑ {upStr}"
            : $"Hajimi Core {snap.Version}  ·  HTTP 127.0.0.1:{hp}  ·  SOCKS5 127.0.0.1:{sp}  ·  ↓ {downStr}  ↑ {upStr}";

        var trayState = _helperClient.IsEnhancedModeActive
            ? TrayVisualState.EnhancedTunActive
            : (SysProxyToggle.IsOn ? TrayVisualState.SystemProxyActive : TrayVisualState.DirectIdle);
        _trayService.CurrentMode = _stateStore.Settings.OutboundMode;
        _trayService.IsSystemProxyEnabled = SysProxyToggle.IsOn;
        _trayService.IsEnhancedTunEnabled = _helperClient.IsEnhancedModeActive;
        _trayService.ActiveProfileTitle = _stateStore.GetActiveManagedProfile()?.Name ?? "默认配置";
        _trayService.UpdateState(trayState, downStr, upStr);
        _trayPopover?.RefreshInPlaceIfVisible(
            snap,
            _themeEngine.ActiveTheme,
            _stateStore.Settings.OutboundMode,
            SysProxyToggle.IsOn,
            _helperClient.IsEnhancedModeActive,
            _trayService.ActiveProfileTitle,
            _trayService.LatestRateSummary);

        if (SectionConnections.Visibility == Visibility.Visible)
        {
            RefreshConnectionsAndLogsView();
        }
    }

    private void RefreshConnectionsAndLogsView()
    {
        _latestConnections = _engine.GetActiveConnections();
        ApplyConnectionFilter();

        var batch = _engine.GetLogsSince(_lastLogSeq);
        if (batch.Logs.Count > 0)
        {
            _lastLogSeq = batch.NextSeq;
            foreach (var entry in batch.Logs)
            {
                _logLines.Add($"{entry.Time} [{entry.Level}] {entry.Msg}");
            }
            if (_logLines.Count > 250)
            {
                _logLines.RemoveRange(0, _logLines.Count - 250);
            }
            RuntimeLogsBox.Text = string.Join(Environment.NewLine, _logLines);
        }
    }

    private void ApplyConnectionFilter()
    {
        string q = ConnFilterBox?.Text.Trim() ?? "";
        if (string.IsNullOrEmpty(q))
        {
            ConnectionsListView.ItemsSource = _latestConnections;
            return;
        }
        ConnectionsListView.ItemsSource = _latestConnections.Where(c =>
            c.Process.Contains(q, StringComparison.OrdinalIgnoreCase) ||
            c.Host.Contains(q, StringComparison.OrdinalIgnoreCase) ||
            c.Policy.Contains(q, StringComparison.OrdinalIgnoreCase) ||
            c.Proto.Contains(q, StringComparison.OrdinalIgnoreCase)).ToList();
    }

    private void OnConnFilterTextChanged(object sender, TextChangedEventArgs e) => ApplyConnectionFilter();

    private void OnKillSingleConnClick(object sender, RoutedEventArgs e)
    {
        if (sender is Button { Tag: ulong cid })
        {
            _engine.CloseConnection(cid);
            RefreshConnectionsAndLogsView();
        }
    }

    private void OnCloseAllConnectionsClick(object sender, RoutedEventArgs e)
    {
        int closed = _engine.CloseConnection(0);
        RefreshConnectionsAndLogsView();
        ShowBanner(InfoBarSeverity.Informational, $"已强制断开 {closed} 条活动连接");
    }

    private void OnClearLogViewClick(object sender, RoutedEventArgs e)
    {
        _logLines.Clear();
        RuntimeLogsBox.Text = "";
    }

    private void OnNavSelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (SectionOverview == null || SectionThemes == null || SectionConnections == null) return;
        string tag = (NavList.SelectedItem as ListViewItem)?.Tag as string ?? "Overview";
        SectionOverview.Visibility = tag == "Overview" ? Visibility.Visible : Visibility.Collapsed;
        SectionPolicies.Visibility = tag == "Policies" ? Visibility.Visible : Visibility.Collapsed;
        SectionConnections.Visibility = tag == "Connections" ? Visibility.Visible : Visibility.Collapsed;
        SectionRules.Visibility = tag == "Rules" ? Visibility.Visible : Visibility.Collapsed;
        SectionSubscriptions.Visibility = tag == "Subscriptions" ? Visibility.Visible : Visibility.Collapsed;
        SectionDns.Visibility = tag == "Dns" ? Visibility.Visible : Visibility.Collapsed;
        SectionDiagnostics.Visibility = tag == "Diagnostics" ? Visibility.Visible : Visibility.Collapsed;
        SectionThemes.Visibility = tag == "Themes" ? Visibility.Visible : Visibility.Collapsed;

        if (tag == "Policies" || tag == "Subscriptions" || tag == "Rules" || tag == "Overview" || tag == "Dns")
        {
            RefreshAllProfileViews();
        }
        else if (tag == "Connections")
        {
            RefreshConnectionsAndLogsView();
        }
    }

    private void RefreshAllProfileViews()
    {
        var snap = _engine.GetStatusSnapshot();
        var rulesSnap = _engine.GetRulesSnapshot();
        UpdateOverviewSummaryLabel(snap, rulesSnap);
        RefreshPolicyGroupCards(snap);
        RefreshRuleSetsAndProvidersView();
        RefreshRulesAndDnsView(rulesSnap);
    }

    private void UpdateOverviewSummaryLabel(EngineStatusSnapshot snap, RulesSnapshotDto rulesSnap)
    {
        if (OverviewProfileSummaryText == null) return;
        OverviewProfileSummaryText.Text = snap.NodeCount > 0
            ? $"已加载 {snap.NodeCount} 个代理节点 · {snap.Groups.Count} 个策略组 · {rulesSnap.BaseRuleCount} 条基础规则（展开后 {snap.RuleCount} 条）· 规则集 {snap.LoadedRuleSetCount}/{snap.RuleSetCount} 已就绪"
            : $"当前已启用内置直连分流配置（{snap.Groups.Count} 个策略组 · {snap.RuleCount} 条展开规则）— 可随时导入 .conf / .yaml 或拉取机场订阅";
        if (EditorStatsLabel != null)
        {
            EditorStatsLabel.Text =
                $"当前解析生效：{snap.NodeCount} 个节点 · {snap.Groups.Count} 个策略组 · {rulesSnap.BaseRuleCount} 条基础规则（展开 {snap.RuleCount} 条）· 规则集 {snap.LoadedRuleSetCount}/{snap.RuleSetCount}";
        }
    }

    private void RefreshManagedProfilesListViews()
    {
        if (RemoteSubsListView != null)
        {
            var subs = _stateStore.GetRemoteSubscriptions();
            RemoteSubsListView.ItemsSource = subs;
            if (RemoteSubsEmptyText != null)
            {
                RemoteSubsEmptyText.Visibility = subs.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
            }
        }
        if (LocalProfilesListView != null)
        {
            var locals = _stateStore.GetLocalImportedProfiles();
            LocalProfilesListView.ItemsSource = locals;
            if (LocalProfilesEmptyText != null)
            {
                LocalProfilesEmptyText.Text = locals.Count == 0
                    ? "尚未导入本地配置文件，点击右侧按钮可导入并托管多个本地档案"
                    : $"共托管 {locals.Count} 份本地导入配置（支持一键切换与删除）";
            }
        }
    }

    private void RefreshRuleSetsAndProvidersView()
    {
        RefreshManagedProfilesListViews();
        if (RuleSetsListView == null || RuleSetsSummaryText == null) return;

        var providers = _engine.GetNodeProviders();
        if (NodeProvidersCard != null && NodeProvidersListView != null && NodeProvidersSummaryText != null)
        {
            NodeProvidersCard.Visibility = providers.Count > 0 ? Visibility.Visible : Visibility.Collapsed;
            int loadedProv = providers.Count(p => p.Loaded);
            int totalProvNodes = providers.Sum(p => p.NodeCount);
            NodeProvidersSummaryText.Text =
                $"外部节点提供者 (proxy-providers / policy-path)：已同步 {loadedProv}/{providers.Count} 个源（共载入 {totalProvNodes} 个外部节点）";
            NodeProvidersListView.ItemsSource = providers;
        }

        var ruleSets = _engine.GetRuleSets();
        int loadedCount = ruleSets.Count(r => r.Loaded);
        RuleSetsSummaryText.Text = ruleSets.Count > 0
            ? $"当前配置共引用 {ruleSets.Count} 个外部规则集（已缓存生效 {loadedCount} 个，支持 .mrs 自动转文本与本地代理加速拉取）"
            : "当前配置仅使用内置与内联规则，未引用额外远程 RULE-SET";
        RuleSetsListView.ItemsSource = ruleSets;
    }

    private void RefreshRulesAndDnsView(RulesSnapshotDto? existing = null)
    {
        var rs = existing ?? _engine.GetRulesSnapshot();
        _latestParsedRules = rs.Rules;
        if (FinalPolicyBadgeText != null)
        {
            FinalPolicyBadgeText.Text = $"兜底策略 FINAL → {rs.FinalPolicy}";
        }
        ApplyParsedRulesFilter();

        if (DnsFakeIpSwitch != null)
        {
            DnsFakeIpSwitch.IsOn = rs.Dns.FakeIpEnabled;
            DnsIpv6Switch.IsOn = rs.Dns.Ipv6Enabled;
            if (rs.Dns.EncryptedUpstreams.Count > 0)
            {
                DnsEncryptedBox.Text = string.Join(", ", rs.Dns.EncryptedUpstreams);
            }
            if (rs.Dns.Nameservers.Count > 0)
            {
                DnsBootstrapBox.Text = string.Join(", ", rs.Dns.Nameservers);
            }
        }
    }

    private void ApplyParsedRulesFilter()
    {
        if (ParsedRulesListView == null) return;
        string q = RuleSearchBox?.Text.Trim() ?? "";
        if (string.IsNullOrEmpty(q))
        {
            ParsedRulesListView.ItemsSource = _latestParsedRules;
            return;
        }
        ParsedRulesListView.ItemsSource = _latestParsedRules.Where(r =>
            r.Type.Contains(q, StringComparison.OrdinalIgnoreCase) ||
            r.Pattern.Contains(q, StringComparison.OrdinalIgnoreCase) ||
            r.Policy.Contains(q, StringComparison.OrdinalIgnoreCase)).ToList();
    }

    private void OnRuleSearchTextChanged(object sender, TextChangedEventArgs e) => ApplyParsedRulesFilter();

    private void UpdateRulesSegmentedStyle()
    {
        if (RulesTabVisualBtn == null || RulesTabRawBtn == null) return;
        var accentBg = ResBrush("HajimiAccentBrush", Color.FromArgb(255, 46, 209, 156));
        var onAccentFg = ResBrush("HajimiOnAccentTextBrush", Color.FromArgb(255, 10, 18, 15));
        var secFg = ResBrush("HajimiTextSecondaryBrush", Color.FromArgb(255, 141, 163, 153));
        var trans = new SolidColorBrush(Colors.Transparent);

        RulesTabVisualBtn.Background = !_showingRawRulesEditor ? accentBg : trans;
        RulesTabVisualBtn.Foreground = !_showingRawRulesEditor ? onAccentFg : secFg;
        RulesTabRawBtn.Background = _showingRawRulesEditor ? accentBg : trans;
        RulesTabRawBtn.Foreground = _showingRawRulesEditor ? onAccentFg : secFg;

        if (RulesVisualContainer != null && RulesRawContainer != null)
        {
            RulesVisualContainer.Visibility = !_showingRawRulesEditor ? Visibility.Visible : Visibility.Collapsed;
            RulesRawContainer.Visibility = _showingRawRulesEditor ? Visibility.Visible : Visibility.Collapsed;
        }
    }

    private void OnRulesTabVisualClick(object sender, RoutedEventArgs e)
    {
        _showingRawRulesEditor = false;
        UpdateRulesSegmentedStyle();
    }

    private void OnRulesTabRawClick(object sender, RoutedEventArgs e)
    {
        _showingRawRulesEditor = true;
        UpdateRulesSegmentedStyle();
    }

    private void OnTestRouteMatchClick(object sender, RoutedEventArgs e)
    {
        string target = RouteTestHostBox.Text.Trim();
        if (string.IsNullOrEmpty(target))
        {
            RouteTestResultText.Text = "请输入域名或 IP";
            return;
        }
        ushort port = 443;
        if (target.Contains("://", StringComparison.Ordinal))
        {
            if (Uri.TryCreate(target, UriKind.Absolute, out Uri? u))
            {
                target = u.Host;
                if (u.Port > 0) port = (ushort)u.Port;
            }
        }
        else if (target.Count(c => c == ':') == 1)
        {
            int idx = target.IndexOf(':');
            if (ushort.TryParse(target[(idx + 1)..], out ushort parsedP))
            {
                port = parsedP;
                target = target[..idx];
            }
        }
        string policy = _engine.EvaluateRoute(target, port, "TCP", "");
        RouteTestResultText.Text = $"{target}:{port}  →  {policy}";
    }

    // =========================================================================
    // macOS-Grade 3-Column Clickable Node Pill Matrix Builder
    // =========================================================================
    private void RefreshPolicyGroupCards(EngineStatusSnapshot? existingSnap = null)
    {
        if (PolicyGroupsPanel == null) return;
        var snap = existingSnap ?? _engine.GetStatusSnapshot();
        if (PolicySummaryText != null)
        {
            PolicySummaryText.Text =
                $"共识别 {snap.Groups.Count} 个策略组 · {snap.NodeCount} 个代理节点 · {snap.RuleCount} 条展开规则 · 外部规则集 {snap.LoadedRuleSetCount}/{snap.RuleSetCount}";
        }

        var nodeMap = new Dictionary<string, ProxyNodeDto>(StringComparer.Ordinal);
        foreach (var node in snap.Nodes)
        {
            if (snap.NodeLatencies.TryGetValue(node.Name, out int rtt))
            {
                node.LatencyMs = rtt;
            }
            nodeMap[node.Name] = node;
        }
        _latestNodes = snap.Nodes;
        ApplyNodeInventoryFilter();

        var groupNames = new HashSet<string>(snap.Groups.Select(x => x.Name), StringComparer.Ordinal);
        string nodeSearch = NodeSearchBox?.Text.Trim() ?? "";

        var panelBrush = ResBrush("HajimiPanelBrush", Color.FromArgb(255, 26, 31, 34));
        var elevBrush = ResBrush("HajimiElevatedPanelBrush", Color.FromArgb(255, 32, 38, 41));
        var borderBrush = ResBrush("HajimiBorderBrush", Color.FromArgb(40, 236, 253, 245));
        var accentBrush = ResBrush("HajimiAccentBrush", Color.FromArgb(255, 46, 209, 156));
        var accentSoftBrush = ResBrush("HajimiAccentSoftBrush", Color.FromArgb(40, 46, 209, 156));
        var accentBorderBrush = ResBrush("HajimiAccentBorderBrush", Color.FromArgb(145, 46, 209, 156));
        var accentTextBrush = ResBrush("HajimiAccentTextBrush", Color.FromArgb(255, 52, 232, 184));
        var priTextBrush = ResBrush("HajimiTextPrimaryBrush", Color.FromArgb(255, 236, 253, 245));
        var secTextBrush = ResBrush("HajimiTextSecondaryBrush", Color.FromArgb(255, 141, 163, 153));
        var warnBrush = new SolidColorBrush(Color.FromArgb(255, 245, 158, 11));
        var dangerBrush = new SolidColorBrush(Color.FromArgb(255, 239, 68, 68));
        var cardRadius = Application.Current.Resources.TryGetValue("HajimiCardCornerRadius", out object? crObj) && crObj is CornerRadius cr
            ? cr : new CornerRadius(14);

        PolicyGroupsPanel.Children.Clear();

        // When in Global Mode, render a dedicated Global Leaf Proxy Node Election card at the top
        if (_stateStore.Settings.OutboundMode == OutboundRoutingMode.Global && snap.Nodes.Count > 0)
        {
            PolicyGroupsPanel.Children.Add(BuildGlobalNodeElectionCard(
                snap, panelBrush, elevBrush, borderBrush, accentBrush, accentSoftBrush,
                accentBorderBrush, accentTextBrush, priTextBrush, secTextBrush, warnBrush, dangerBrush, cardRadius));
        }

        foreach (var g in snap.Groups)
        {
            var visibleMembers = string.IsNullOrEmpty(nodeSearch)
                ? g.Members
                : g.Members.Where(m =>
                    m.Contains(nodeSearch, StringComparison.OrdinalIgnoreCase) ||
                    m == g.Selected ||
                    (nodeMap.TryGetValue(m, out var nd) &&
                     (nd.Type.Contains(nodeSearch, StringComparison.OrdinalIgnoreCase) ||
                      nd.Server.Contains(nodeSearch, StringComparison.OrdinalIgnoreCase)))).ToList();
            if (visibleMembers.Count == 0) visibleMembers = g.Members;

            var cardStack = new StackPanel { Spacing = 12 };

            // Card Header: Group Name + Kind Badge + Member Count + Active Selected Badge
            var hdrGrid = new Grid { ColumnSpacing = 10 };
            hdrGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            hdrGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

            var leftRow = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 8, VerticalAlignment = VerticalAlignment.Center };
            leftRow.Children.Add(new TextBlock
            {
                Text = g.Name,
                FontSize = 15,
                FontWeight = Microsoft.UI.Text.FontWeights.Bold,
                Foreground = priTextBrush,
                VerticalAlignment = VerticalAlignment.Center
            });
            var kindBadge = new Border
            {
                Background = accentSoftBrush,
                CornerRadius = new CornerRadius(5),
                Padding = new Thickness(7, 2, 7, 2),
                VerticalAlignment = VerticalAlignment.Center,
                Child = new TextBlock
                {
                    Text = $"{g.KindLabel} · {g.Members.Count}",
                    FontSize = 11,
                    FontWeight = Microsoft.UI.Text.FontWeights.SemiBold,
                    Foreground = accentTextBrush
                }
            };
            leftRow.Children.Add(kindBadge);
            hdrGrid.Children.Add(leftRow);

            var activeSummaryBadge = new Border
            {
                Background = elevBrush,
                BorderBrush = borderBrush,
                BorderThickness = new Thickness(1),
                CornerRadius = new CornerRadius(6),
                Padding = new Thickness(10, 3, 10, 3),
                VerticalAlignment = VerticalAlignment.Center,
                Child = new TextBlock
                {
                    Text = $"当前生效：{g.Selected}",
                    FontSize = 11.5,
                    FontWeight = Microsoft.UI.Text.FontWeights.SemiBold,
                    Foreground = accentTextBrush
                }
            };
            Grid.SetColumn(activeSummaryBadge, 1);
            hdrGrid.Children.Add(activeSummaryBadge);
            cardStack.Children.Add(hdrGrid);

            // 3-Column Clickable Node Pill Matrix Grid
            const int columns = 3;
            int rows = Math.Max(1, (visibleMembers.Count + columns - 1) / columns);
            var matrixGrid = new Grid { ColumnSpacing = 10, RowSpacing = 10 };
            for (int c = 0; c < columns; c++)
            {
                matrixGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            }
            for (int r = 0; r < rows; r++)
            {
                matrixGrid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            }

            string capturedGroup = g.Name;
            for (int idx = 0; idx < visibleMembers.Count; idx++)
            {
                string memberName = visibleMembers[idx];
                bool isSelected = string.Equals(memberName, g.Selected, StringComparison.Ordinal);

                string subLabel = "代理节点";
                string rttLabel = "--";
                Brush rttBrush = secTextBrush;

                if (string.Equals(memberName, "DIRECT", StringComparison.OrdinalIgnoreCase))
                {
                    subLabel = "BUILTIN · 直连出口";
                    rttLabel = "直连";
                    rttBrush = accentTextBrush;
                }
                else if (memberName.StartsWith("REJECT", StringComparison.OrdinalIgnoreCase))
                {
                    subLabel = "BUILTIN · 拦截策略";
                    rttLabel = "阻断";
                    rttBrush = warnBrush;
                }
                else if (groupNames.Contains(memberName))
                {
                    subLabel = "POLICY GROUP · 嵌套组";
                    rttLabel = "策略组";
                    rttBrush = secTextBrush;
                }
                else if (nodeMap.TryGetValue(memberName, out var ndInfo))
                {
                    subLabel = ndInfo.TypeBadge;
                    if (ndInfo.LatencyMs >= 0)
                    {
                        rttLabel = $"{ndInfo.LatencyMs} ms";
                        rttBrush = ndInfo.LatencyMs < 150 ? accentTextBrush : (ndInfo.LatencyMs < 350 ? warnBrush : dangerBrush);
                    }
                    else if (ndInfo.LatencyMs != int.MinValue)
                    {
                        rttLabel = "超时";
                        rttBrush = dangerBrush;
                    }
                }

                var pillInner = new Grid { ColumnSpacing = 8 };
                pillInner.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
                pillInner.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
                pillInner.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

                var dot = new Microsoft.UI.Xaml.Shapes.Ellipse
                {
                    Width = 8,
                    Height = 8,
                    Fill = isSelected ? accentBrush : borderBrush,
                    VerticalAlignment = VerticalAlignment.Center
                };
                pillInner.Children.Add(dot);

                var textCol = new StackPanel { Spacing = 1, VerticalAlignment = VerticalAlignment.Center };
                textCol.Children.Add(new TextBlock
                {
                    Text = memberName,
                    FontSize = 12.5,
                    FontWeight = isSelected ? Microsoft.UI.Text.FontWeights.Bold : Microsoft.UI.Text.FontWeights.SemiBold,
                    Foreground = priTextBrush,
                    TextTrimming = TextTrimming.CharacterEllipsis
                });
                textCol.Children.Add(new TextBlock
                {
                    Text = subLabel,
                    FontSize = 10.5,
                    Foreground = secTextBrush,
                    TextTrimming = TextTrimming.CharacterEllipsis
                });
                Grid.SetColumn(textCol, 1);
                pillInner.Children.Add(textCol);

                var rttText = new TextBlock
                {
                    Text = rttLabel,
                    FontSize = 11.5,
                    FontWeight = Microsoft.UI.Text.FontWeights.SemiBold,
                    Foreground = rttBrush,
                    VerticalAlignment = VerticalAlignment.Center
                };
                Grid.SetColumn(rttText, 2);
                pillInner.Children.Add(rttText);

                var pillBtn = new Button
                {
                    HorizontalAlignment = HorizontalAlignment.Stretch,
                    HorizontalContentAlignment = HorizontalAlignment.Stretch,
                    Padding = new Thickness(12, 9, 12, 9),
                    CornerRadius = new CornerRadius(10),
                    Background = isSelected ? accentSoftBrush : elevBrush,
                    BorderBrush = isSelected ? accentBorderBrush : borderBrush,
                    BorderThickness = new Thickness(isSelected ? 1.5 : 1.0),
                    Content = pillInner
                };

                string chosenMember = memberName;
                pillBtn.Click += (_, _) =>
                {
                    if (_engine.SelectPolicy(capturedGroup, chosenMember))
                    {
                        _stateStore.Settings.SelectedPolicies[capturedGroup] = chosenMember;
                        _stateStore.SaveSettings();
                        RefreshPolicyGroupCards();
                    }
                };

                Grid.SetRow(pillBtn, idx / columns);
                Grid.SetColumn(pillBtn, idx % columns);
                matrixGrid.Children.Add(pillBtn);
            }

            cardStack.Children.Add(matrixGrid);

            var groupCard = new Border
            {
                Background = panelBrush,
                BorderBrush = borderBrush,
                BorderThickness = new Thickness(1),
                CornerRadius = cardRadius,
                Padding = new Thickness(18, 15, 18, 16),
                Child = cardStack
            };
            PolicyGroupsPanel.Children.Add(groupCard);
        }
    }

    private void ApplyNodeInventoryFilter()
    {
        if (NodesListView == null) return;
        string q = NodeSearchBox?.Text.Trim() ?? "";
        var filtered = string.IsNullOrEmpty(q)
            ? _latestNodes
            : _latestNodes.Where(n =>
                n.Name.Contains(q, StringComparison.OrdinalIgnoreCase) ||
                n.Type.Contains(q, StringComparison.OrdinalIgnoreCase) ||
                n.Server.Contains(q, StringComparison.OrdinalIgnoreCase)).ToList();

        NodesListView.ItemsSource = filtered;
        if (FilteredNodeCountText != null)
        {
            FilteredNodeCountText.Text = string.IsNullOrEmpty(q)
                ? $"共 {_latestNodes.Count} 个节点"
                : $"筛选显示 {filtered.Count} / {_latestNodes.Count} 个节点";
        }
    }

    private void OnNodeSearchTextChanged(object sender, TextChangedEventArgs e)
    {
        RefreshPolicyGroupCards();
    }

    private async void OnProbeSingleNodeClick(object sender, RoutedEventArgs e)
    {
        if (sender is not Button { Tag: string nodeName } btn) return;
        btn.IsEnabled = false;
        btn.Content = "...";
        try
        {
            int rtt = await Task.Run(() => _engine.ProbeNodeLatencyMs(nodeName, 3000));
            RefreshPolicyGroupCards();
            ShowBanner(
                rtt >= 0 ? InfoBarSeverity.Success : InfoBarSeverity.Warning,
                rtt >= 0 ? $"节点「{nodeName}」握手延迟：{rtt} ms" : $"节点「{nodeName}」连接超时或不可达");
        }
        finally
        {
            btn.IsEnabled = true;
            btn.Content = "测速";
        }
    }

    private async void OnProbeAllNodesClick(object sender, RoutedEventArgs e)
    {
        ProbeAllBtn.IsEnabled = false;
        ProbeAllBtn.Content = "正在并发测速...";
        try
        {
            var preSnap = _engine.GetStatusSnapshot();
            if (preSnap.NodeCount == 0)
            {
                RefreshAllProfileViews();
                ShowBanner(InfoBarSeverity.Warning, "当前配置尚未包含远程代理节点，请先导入 .conf / .yaml 或拉取机场订阅");
                return;
            }
            int healthy = await Task.Run(() => _engine.ProbeAllNodes(2500));
            RefreshAllProfileViews();
            ShowBanner(InfoBarSeverity.Success,
                $"并发测速完成：{healthy} / {preSnap.NodeCount} 个节点响应正常（URL-Test / Fallback / Smart 策略组已自动优选）");
        }
        finally
        {
            ProbeAllBtn.IsEnabled = true;
            ProbeAllBtn.Content = "⚡ 并发测速全部节点";
        }
    }

    private void ApplyRoutingMode(OutboundRoutingMode mode, bool persist = true)
    {
        _engine.SetMode(mode);
        _trayService.CurrentMode = mode;

        var accentBg = ResBrush("HajimiAccentBrush", Color.FromArgb(255, 46, 209, 156));
        var onAccentFg = ResBrush("HajimiOnAccentTextBrush", Color.FromArgb(255, 10, 18, 15));
        var secFg = ResBrush("HajimiTextSecondaryBrush", Color.FromArgb(255, 141, 163, 153));
        var trans = new SolidColorBrush(Colors.Transparent);

        void StyleSeg(Button btn, bool active)
        {
            btn.Background = active ? accentBg : trans;
            btn.Foreground = active ? onAccentFg : secFg;
        }

        StyleSeg(ModeRuleBtn, mode == OutboundRoutingMode.Rule);
        StyleSeg(ModeGlobalBtn, mode == OutboundRoutingMode.Global);
        StyleSeg(ModeDirectBtn, mode == OutboundRoutingMode.Direct);

        if (OverviewActiveModeText != null)
        {
            OverviewActiveModeText.Text = mode switch
            {
                OutboundRoutingMode.Global => "全局代理 (Global)",
                OutboundRoutingMode.Direct => "全局直连 (Direct)",
                _ => "规则分流 (Rule)"
            };
        }

        if (persist)
        {
            _stateStore.Settings.OutboundMode = mode;
            _stateStore.SaveSettings();
            RefreshPolicyGroupCards();
        }

        if (_trayPopover is { IsPopoverVisible: true })
        {
            _trayPopover.RefreshInPlaceIfVisible(
                _engine.GetStatusSnapshot(),
                _themeEngine.ActiveTheme,
                mode,
                SysProxyToggle.IsOn,
                _helperClient.IsEnhancedModeActive,
                _stateStore.GetActiveManagedProfile()?.Name ?? "默认配置",
                _trayService.LatestRateSummary);
        }
    }

    private Border BuildGlobalNodeElectionCard(
        EngineStatusSnapshot snap, Brush panelBrush, Brush elevBrush, Brush borderBrush,
        Brush accentBrush, Brush accentSoftBrush, Brush accentBorderBrush, Brush accentTextBrush,
        Brush priTextBrush, Brush secTextBrush, Brush warnBrush, Brush dangerBrush, CornerRadius cardRadius)
    {
        var stack = new StackPanel { Spacing = 12 };
        var hdr = new Grid { ColumnSpacing = 10 };
        hdr.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        hdr.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

        var leftInfo = new StackPanel { Spacing = 2 };
        leftInfo.Children.Add(new TextBlock
        {
            Text = "🌐 全局代理节点直选（Global 模式专属）",
            FontSize = 15,
            FontWeight = Microsoft.UI.Text.FontWeights.Bold,
            Foreground = priTextBrush
        });
        leftInfo.Children.Add(new TextBlock
        {
            Text = "全局模式下绕过分流规则与下方策略组，所有流量直接走此处选举的落地代理节点",
            FontSize = 11.5,
            Foreground = secTextBrush
        });
        hdr.Children.Add(leftInfo);

        var curBadge = new Border
        {
            Background = accentSoftBrush,
            BorderBrush = accentBorderBrush,
            BorderThickness = new Thickness(1),
            CornerRadius = new CornerRadius(6),
            Padding = new Thickness(10, 4, 10, 4),
            VerticalAlignment = VerticalAlignment.Center,
            Child = new TextBlock
            {
                Text = $"当前全局出站：{snap.EffectiveGlobalNode}",
                FontSize = 11.5,
                FontWeight = Microsoft.UI.Text.FontWeights.Bold,
                Foreground = accentTextBrush
            }
        };
        Grid.SetColumn(curBadge, 1);
        hdr.Children.Add(curBadge);
        stack.Children.Add(hdr);

        var items = new List<(string Key, string Title, string Sub, string Rtt, Brush RttFg)>();
        items.Add(("__AUTO_FASTEST__", "⚡ 自动最低延迟优选", $"当前优选：{snap.EffectiveGlobalNode}", "AUTO", accentTextBrush));
        foreach (var nd in snap.Nodes)
        {
            bool hasRtt = snap.NodeLatencies.TryGetValue(nd.Name, out int rtt);
            string rttStr = !hasRtt ? "待测速" : (rtt >= 0 ? $"{rtt} ms" : "超时");
            Brush rttFg = !hasRtt ? secTextBrush : (rtt < 0 ? dangerBrush : (rtt < 160 ? accentTextBrush : warnBrush));
            items.Add((nd.Name, nd.Name, nd.TypeBadge, rttStr, rttFg));
        }

        const int columns = 3;
        int rows = Math.Max(1, (items.Count + columns - 1) / columns);
        var grid = new Grid { ColumnSpacing = 10, RowSpacing = 10 };
        for (int c = 0; c < columns; c++) grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        for (int r = 0; r < rows; r++) grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });

        string selGlobal = string.IsNullOrEmpty(snap.GlobalSelectedNode) ? "__AUTO_FASTEST__" : snap.GlobalSelectedNode;
        for (int i = 0; i < items.Count; i++)
        {
            var it = items[i];
            bool isSel = string.Equals(selGlobal, it.Key, StringComparison.Ordinal);

            var inner = new Grid { ColumnSpacing = 8 };
            inner.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
            inner.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            inner.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

            inner.Children.Add(new Microsoft.UI.Xaml.Shapes.Ellipse
            {
                Width = 8,
                Height = 8,
                Fill = isSel ? accentBrush : borderBrush,
                VerticalAlignment = VerticalAlignment.Center
            });

            var col = new StackPanel { Spacing = 1, VerticalAlignment = VerticalAlignment.Center };
            col.Children.Add(new TextBlock
            {
                Text = it.Title,
                FontSize = 12.5,
                FontWeight = isSel ? Microsoft.UI.Text.FontWeights.Bold : Microsoft.UI.Text.FontWeights.SemiBold,
                Foreground = priTextBrush,
                TextTrimming = TextTrimming.CharacterEllipsis
            });
            col.Children.Add(new TextBlock
            {
                Text = it.Sub,
                FontSize = 10.5,
                Foreground = secTextBrush,
                TextTrimming = TextTrimming.CharacterEllipsis
            });
            Grid.SetColumn(col, 1);
            inner.Children.Add(col);

            var rttTb = new TextBlock
            {
                Text = it.Rtt,
                FontSize = 11.5,
                FontWeight = Microsoft.UI.Text.FontWeights.SemiBold,
                Foreground = it.RttFg,
                VerticalAlignment = VerticalAlignment.Center
            };
            Grid.SetColumn(rttTb, 2);
            inner.Children.Add(rttTb);

            var btn = new Button
            {
                HorizontalAlignment = HorizontalAlignment.Stretch,
                HorizontalContentAlignment = HorizontalAlignment.Stretch,
                Padding = new Thickness(12, 9, 12, 9),
                CornerRadius = new CornerRadius(10),
                Background = isSel ? accentSoftBrush : elevBrush,
                BorderBrush = isSel ? accentBorderBrush : borderBrush,
                BorderThickness = new Thickness(isSel ? 1.5 : 1.0),
                Content = inner
            };
            string capturedKey = it.Key;
            btn.Click += (_, _) => SelectGlobalNodeFromTray(capturedKey);
            Grid.SetRow(btn, i / columns);
            Grid.SetColumn(btn, i % columns);
            grid.Children.Add(btn);
        }

        stack.Children.Add(grid);
        return new Border
        {
            Background = panelBrush,
            BorderBrush = accentBorderBrush,
            BorderThickness = new Thickness(1.2),
            CornerRadius = cardRadius,
            Padding = new Thickness(18, 15, 18, 16),
            Child = stack
        };
    }

    private TrayPopoverWindow EnsureTrayPopoverWindow()
    {
        if (_trayPopover != null) return _trayPopover;
        var pop = new TrayPopoverWindow();
        pop.ModeSelected += m => ApplyRoutingMode(m);
        pop.PolicyGroupMemberSelected += SelectPolicyGroupFromTray;
        pop.GlobalNodeSelected += SelectGlobalNodeFromTray;
        pop.ProbeNodesRequested += () => OnProbeAllNodesClick(this, new RoutedEventArgs());
        pop.ToggleEnhancedTunRequested += () => { EnhancedTunToggle.IsOn = !EnhancedTunToggle.IsOn; };
        pop.ToggleSystemProxyRequested += () => { SysProxyToggle.IsOn = !SysProxyToggle.IsOn; };
        pop.RefreshSubscriptionRequested += () => { _ = SilentRefreshSubscriptionAndRuleSetsAsync(); };
        pop.OpenMainWindowRequested += () =>
        {
            _trayService.ShowMainWindow();
            Activate();
        };
        pop.ExitAppRequested += () =>
        {
            _explicitExitRequested = true;
            Close();
        };
        _trayPopover = pop;
        return pop;
    }

    private void ToggleTrayPopoverCard()
    {
        var pop = EnsureTrayPopoverWindow();
        if (pop.IsPopoverVisible)
        {
            pop.HidePopover();
            return;
        }
        pop.ShowNearTrayAndRefresh(
            _engine.GetStatusSnapshot(),
            _themeEngine.ActiveTheme,
            _stateStore.Settings.OutboundMode,
            SysProxyToggle.IsOn,
            _helperClient.IsEnhancedModeActive,
            _stateStore.GetActiveManagedProfile()?.Name ?? "默认配置",
            _trayService.LatestRateSummary);
    }

    private void SelectPolicyGroupFromTray(string groupName, string memberName)
    {
        if (_engine.SelectPolicy(groupName, memberName))
        {
            _stateStore.Settings.SelectedPolicies[groupName] = memberName;
            _stateStore.SaveSettings();
            var snap = _engine.GetStatusSnapshot();
            RefreshPolicyGroupCards(snap);
            _trayPopover?.RefreshInPlaceIfVisible(
                snap,
                _themeEngine.ActiveTheme,
                _stateStore.Settings.OutboundMode,
                SysProxyToggle.IsOn,
                _helperClient.IsEnhancedModeActive,
                _stateStore.GetActiveManagedProfile()?.Name ?? "默认配置",
                _trayService.LatestRateSummary);
        }
    }

    private void SelectGlobalNodeFromTray(string nodeName)
    {
        if (_engine.SetGlobalNode(nodeName))
        {
            _stateStore.Settings.GlobalSelectedNode = nodeName;
            _stateStore.SaveSettings();
            var snap = _engine.GetStatusSnapshot();
            RefreshPolicyGroupCards(snap);
            _trayPopover?.RefreshInPlaceIfVisible(
                snap,
                _themeEngine.ActiveTheme,
                _stateStore.Settings.OutboundMode,
                SysProxyToggle.IsOn,
                _helperClient.IsEnhancedModeActive,
                _stateStore.GetActiveManagedProfile()?.Name ?? "默认配置",
                _trayService.LatestRateSummary);
        }
    }

    private void OnModeRuleClick(object sender, RoutedEventArgs e) => ApplyRoutingMode(OutboundRoutingMode.Rule);
    private void OnModeGlobalClick(object sender, RoutedEventArgs e) => ApplyRoutingMode(OutboundRoutingMode.Global);
    private void OnModeDirectClick(object sender, RoutedEventArgs e) => ApplyRoutingMode(OutboundRoutingMode.Direct);

    private void OnSysProxyToggled(object sender, RoutedEventArgs e)
    {
        if (_suppressToggleEvents) return;
        try
        {
            if (SysProxyToggle.IsOn)
            {
                ushort port = _engine.BoundHttpPort;
                if (port == 0) throw new InvalidOperationException("HTTP 入站监听尚未绑定有效端口");
                _engine.EnableSystemProxy(port);
                _stateStore.Settings.SystemProxyEnabled = true;
                _stateStore.SaveSettings();
                ShowBanner(InfoBarSeverity.Success, $"WinINet 系统代理已开启并指向 127.0.0.1:{port}（含快照归属权保护）");
            }
            else
            {
                _stateStore.Settings.SystemProxyEnabled = false;
                _stateStore.SaveSettings();
                if (!_engine.DisableSystemProxy(out string warn))
                    ShowBanner(InfoBarSeverity.Warning, warn);
            }
        }
        catch (Exception ex)
        {
            _suppressToggleEvents = true;
            SysProxyToggle.IsOn = false;
            _suppressToggleEvents = false;
            ShowBanner(InfoBarSeverity.Error, ex.Message);
        }
    }

    private async void OnEnhancedTunToggled(object sender, RoutedEventArgs e)
    {
        if (_suppressToggleEvents) return;
        try
        {
            if (EnhancedTunToggle.IsOn)
            {
                string? physNic = NetworkPowerWatcher.DetectPrimaryPhysicalNic(out _);
                if (!string.IsNullOrEmpty(physNic)) _engine.NotifyNetworkChange(physNic);
                var curSnap = _engine.GetStatusSnapshot();
                await _helperClient.EnableEnhancedModeAsync(
                    _engine,
                    bypassAddresses: curSnap.BypassServerIps,
                    excludedRoutes: ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]);
                ShowBanner(InfoBarSeverity.Success,
                    $"TUN 增强模式已激活（{_helperClient.ActiveTunnelInterface} · 16 MiB SPSC 零拷贝环 + 全锥形 UDP NAT + WFP 防泄漏）");
            }
            else
            {
                await _helperClient.DisableEnhancedModeAsync(_engine);
                ShowBanner(InfoBarSeverity.Informational, "TUN 增强模式已关闭，系统路由与 DNS 已恢复");
            }
        }
        catch (Exception ex)
        {
            _suppressToggleEvents = true;
            EnhancedTunToggle.IsOn = false;
            _suppressToggleEvents = false;
            ShowBanner(InfoBarSeverity.Error, ex.Message);
        }
    }

    private void OnCloseToTrayCheckClicked(object sender, RoutedEventArgs e)
    {
        bool on = CloseToTrayCheck.IsChecked == true;
        _stateStore.Settings.CloseToTray = on;
        _stateStore.Settings.MinimizeToTray = on;
        _trayService.MinimizeToTrayOnMinimize = on;
        _stateStore.SaveSettings();
    }

    private void OnHideToTrayClick(object sender, RoutedEventArgs e)
    {
        _trayService.HideMainWindow();
    }

    private void OnAutoStartCheckClicked(object sender, RoutedEventArgs e)
    {
        TrayIconService.SetAutoStart(AutoStartCheck.IsChecked == true);
        ShowBanner(InfoBarSeverity.Informational,
            AutoStartCheck.IsChecked == true ? "已开启开机自动启动（静默驻留托盘）" : "已关闭开机自动启动");
    }

    public void RestoreFromTray()
    {
        _trayService.ShowMainWindow();
        Activate();
    }

    private void OnExplicitExitClick(object sender, RoutedEventArgs e)
    {
        _explicitExitRequested = true;
        Close();
    }

    private void OnTrayMenuAction(TrayMenuAction action)
    {
        DispatcherQueue.TryEnqueue(() =>
        {
            switch (action)
            {
                case TrayMenuAction.ShowWindow:
                    _trayService.ShowMainWindow();
                    Activate();
                    break;
                case TrayMenuAction.ModeRule:
                    ApplyRoutingMode(OutboundRoutingMode.Rule);
                    break;
                case TrayMenuAction.ModeGlobal:
                    ApplyRoutingMode(OutboundRoutingMode.Global);
                    break;
                case TrayMenuAction.ModeDirect:
                    ApplyRoutingMode(OutboundRoutingMode.Direct);
                    break;
                case TrayMenuAction.ToggleSystemProxy:
                    SysProxyToggle.IsOn = !SysProxyToggle.IsOn;
                    break;
                case TrayMenuAction.ToggleEnhancedTun:
                    EnhancedTunToggle.IsOn = !EnhancedTunToggle.IsOn;
                    break;
                case TrayMenuAction.ProbeAllNodes:
                    OnProbeAllNodesClick(this, new RoutedEventArgs());
                    break;
                case TrayMenuAction.RefreshSubscription:
                    _ = SilentRefreshSubscriptionAndRuleSetsAsync();
                    break;
                case TrayMenuAction.DisconnectAll:
                    _engine.CloseConnection(0);
                    break;
                case TrayMenuAction.FlushDns:
                    _engine.FlushDnsAndFakeIp();
                    break;
                case TrayMenuAction.ToggleAutoStart:
                    bool nextAuto = !TrayIconService.IsAutoStartEnabled();
                    TrayIconService.SetAutoStart(nextAuto);
                    AutoStartCheck.IsChecked = nextAuto;
                    break;
                case TrayMenuAction.ExitApp:
                    _explicitExitRequested = true;
                    Close();
                    break;
            }
        });
    }

    private void OnAppWindowClosing(AppWindow sender, AppWindowClosingEventArgs args)
    {
        if (!_explicitExitRequested && _stateStore.Settings.CloseToTray)
        {
            args.Cancel = true;
            _trayService.HideMainWindow();
        }
    }

    private void OnCopyPwshClick(object sender, RoutedEventArgs e)
    {
        TrayIconService.CopyTerminalProxyCommands("pwsh", _engine.BoundHttpPort, _engine.BoundSocksPort);
        ShowBanner(InfoBarSeverity.Success, "已复制 PowerShell 终端代理环境变量命令到剪贴板");
    }

    private void OnFlushDnsClick(object sender, RoutedEventArgs e)
    {
        _engine.FlushDnsAndFakeIp();
        ShowBanner(InfoBarSeverity.Success, "已清空加密 DNS 缓存与 Fake-IP 映射池");
    }

    private void OnSaveDnsConfigClick(object sender, RoutedEventArgs e)
    {
        try
        {
            string current = NormalizeAndMaybeDecodeProfileText(ProfileEditorBox.Text);
            if (string.IsNullOrWhiteSpace(current)) current = DefaultStarterProfile;

            string encDns = DnsEncryptedBox.Text.Trim();
            string bootDns = DnsBootstrapBox.Text.Trim();
            bool fakeIp = DnsFakeIpSwitch.IsOn;
            bool ipv6 = DnsIpv6Switch.IsOn;

            string updated = ApplyDnsOverridesToProfileText(current, bootDns, encDns, fakeIp, ipv6);
            ProfileEditorBox.Text = updated;
            _engine.LoadProfileText(updated);
            _stateStore.SaveActiveProfileText(updated);
            _stateStore.LoadCachedProvidersAndRuleSetsIntoEngine(_engine);
            RestoreSavedPolicySelections();
            _engine.FlushDnsAndFakeIp();
            RefreshAllProfileViews();
            ShowBanner(InfoBarSeverity.Success, "DNS 与 Fake-IP 配置已写入当前档案并实时生效");
        }
        catch (Exception ex)
        {
            ShowBanner(InfoBarSeverity.Error, $"应用 DNS 设置失败：{ex.Message}");
        }
    }

    private static string ApplyDnsOverridesToProfileText(
        string profileText, string bootDns, string encDns, bool fakeIp, bool ipv6)
    {
        bool isSurge = profileText.Contains("[General]", StringComparison.OrdinalIgnoreCase) ||
                       profileText.Contains("[Proxy]", StringComparison.OrdinalIgnoreCase);

        if (isSurge)
        {
            var lines = profileText.Split('\n').ToList();
            int genIdx = lines.FindIndex(l => l.Trim().Equals("[General]", StringComparison.OrdinalIgnoreCase));
            if (genIdx < 0)
            {
                lines.Insert(0, "[General]");
                genIdx = 0;
            }
            int secEnd = lines.Count;
            for (int i = genIdx + 1; i < lines.Count; i++)
            {
                string t = lines[i].Trim();
                if (t.StartsWith('[') && t.EndsWith(']') && !t.Contains('='))
                {
                    secEnd = i;
                    break;
                }
            }
            // Remove existing dns keys inside [General]
            for (int i = secEnd - 1; i > genIdx; i--)
            {
                string t = lines[i].TrimStart();
                if (t.StartsWith("dns-server", StringComparison.OrdinalIgnoreCase) ||
                    t.StartsWith("encrypted-dns-server", StringComparison.OrdinalIgnoreCase) ||
                    t.StartsWith("enhanced-mode", StringComparison.OrdinalIgnoreCase) ||
                    t.StartsWith("ipv6", StringComparison.OrdinalIgnoreCase))
                {
                    lines.RemoveAt(i);
                }
            }
            var inject = new List<string>
            {
                $"ipv6 = {(ipv6 ? "true" : "false")}"
            };
            if (!string.IsNullOrWhiteSpace(bootDns)) inject.Add($"dns-server = {bootDns}");
            if (!string.IsNullOrWhiteSpace(encDns)) inject.Add($"encrypted-dns-server = {encDns}");
            if (fakeIp) inject.Add("enhanced-mode = fake-ip");
            lines.InsertRange(genIdx + 1, inject);
            return string.Join("\n", lines);
        }

        // Clash / Mihomo YAML: replace or prepend top-level `ipv6:` and `dns:` block
        var yamlLines = profileText.Split('\n').ToList();
        var cleaned = new List<string>(yamlLines.Count + 12);
        bool skippingDnsBlock = false;
        foreach (string line in yamlLines)
        {
            string trimmed = line.Trim();
            bool topLevel = line.Length > 0 && line[0] != ' ' && line[0] != '\t' && line[0] != '#';
            if (topLevel)
            {
                if (trimmed.StartsWith("dns:", StringComparison.OrdinalIgnoreCase))
                {
                    skippingDnsBlock = true;
                    continue;
                }
                skippingDnsBlock = false;
                if (trimmed.StartsWith("ipv6:", StringComparison.OrdinalIgnoreCase))
                    continue;
            }
            if (skippingDnsBlock) continue;
            cleaned.Add(line);
        }

        var dnsBlock = new List<string>
        {
            $"ipv6: {(ipv6 ? "true" : "false")}",
            "dns:",
            "  enable: true",
            $"  ipv6: {(ipv6 ? "true" : "false")}",
            $"  enhanced-mode: {(fakeIp ? "fake-ip" : "redir-host")}",
            "  nameserver:"
        };
        foreach (string s in bootDns.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            dnsBlock.Add($"    - {s}");
        }
        foreach (string s in encDns.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            dnsBlock.Add($"    - {s}");
        }
        cleaned.InsertRange(0, dnsBlock);
        return string.Join("\n", cleaned);
    }

    private async void OnApplyProfileEditorClick(object sender, RoutedEventArgs e)
    {
        try
        {
            string text = NormalizeAndMaybeDecodeProfileText(ProfileEditorBox.Text);
            _engine.LoadProfileText(text);
            _stateStore.LoadCachedProvidersAndRuleSetsIntoEngine(_engine);
            RestoreSavedPolicySelections();
            var snap = _engine.GetStatusSnapshot();
            _stateStore.SaveActiveProfileText(text, snap.NodeCount, snap.Groups.Count);
            RefreshAllProfileViews();
            ShowBanner(InfoBarSeverity.Success,
                $"配置已保存并热重载：识别 {snap.NodeCount} 个节点、{snap.Groups.Count} 个策略组、{snap.RuleSetCount} 个规则集");
            int updatedRs = await _stateStore.RefreshRemoteRuleSetsAsync(_engine, SubHttp);
            if (updatedRs > 0)
            {
                RestoreSavedPolicySelections();
                RefreshAllProfileViews();
                var afterSnap = _engine.GetStatusSnapshot();
                ShowBanner(InfoBarSeverity.Success,
                    $"配置及远程规则集已全部就绪：{afterSnap.NodeCount} 个节点 · {afterSnap.Groups.Count} 个策略组 · 规则集 {afterSnap.LoadedRuleSetCount}/{afterSnap.RuleSetCount}（共 {afterSnap.RuleCount} 条生效规则）");
            }
        }
        catch (Exception ex)
        {
            ShowBanner(InfoBarSeverity.Error, $"配置校验未通过：{ex.Message}");
        }
    }

    private async void OnImportProfileFileClick(object sender, RoutedEventArgs e)
    {
        string? filePath = PickFileWin32(
            "代理配置文件 (*.conf;*.yaml;*.yml;*.txt)\0*.conf;*.yaml;*.yml;*.txt\0所有文件 (*.*)\0*.*\0\0",
            "选择 Surge (.conf) 或 Clash / Mihomo (.yaml) 配置文件");
        if (string.IsNullOrEmpty(filePath)) return;

        try
        {
            string content = ReadProfileFileSmart(filePath);
            ProfileEditorBox.Text = content;
            _engine.LoadProfileText(content);
            _stateStore.LoadCachedProvidersAndRuleSetsIntoEngine(_engine);
            RestoreSavedPolicySelections();
            var snap = _engine.GetStatusSnapshot();
            _stateStore.AddImportedLocalProfile(filePath, content, snap.NodeCount, snap.Groups.Count, setActive: true);
            RefreshAllProfileViews();
            string fileName = System.IO.Path.GetFileName(filePath);
            ShowBanner(InfoBarSeverity.Success,
                $"已导入 {fileName}：{snap.NodeCount} 个节点、{snap.Groups.Count} 个策略组、{snap.RuleSetCount} 个规则集（正在后台同步外部源...）");

            _ = await _stateStore.RefreshRemoteRuleSetsAsync(_engine, SubHttp);
            RestoreSavedPolicySelections();
            RefreshAllProfileViews();
            var afterSnap = _engine.GetStatusSnapshot();
            ShowBanner(InfoBarSeverity.Success,
                $"导入完成（{fileName}）：{afterSnap.NodeCount} 个节点 · {afterSnap.Groups.Count} 个策略组 · 规则集 {afterSnap.LoadedRuleSetCount}/{afterSnap.RuleSetCount}（共 {afterSnap.RuleCount} 条生效规则）");
        }
        catch (Exception ex)
        {
            ShowBanner(InfoBarSeverity.Error, $"导入配置文件失败：{ex.Message}");
        }
    }

    private string? PickFileWin32(string filter, string title)
    {
        const int OFN_PATHMUSTEXIST = 0x00000800;
        const int OFN_FILEMUSTEXIST = 0x00001000;
        const int OFN_NOCHANGEDIR = 0x00000008;
        const int OFN_EXPLORER = 0x00080000;
        const int maxChars = 4096;

        IntPtr filterPtr = Marshal.AllocHGlobal(filter.Length * sizeof(char));
        IntPtr filePtr = Marshal.AllocHGlobal(maxChars * sizeof(char));
        IntPtr titlePtr = Marshal.StringToHGlobalUni(title);
        try
        {
            Marshal.Copy(filter.ToCharArray(), 0, filterPtr, filter.Length);
            unsafe
            {
                new Span<byte>((void*)filePtr, maxChars * sizeof(char)).Clear();
            }

            var ofn = new OPENFILENAMEW
            {
                lStructSize = Marshal.SizeOf<OPENFILENAMEW>(),
                hwndOwner = WindowNative.GetWindowHandle(this),
                lpstrFilter = filterPtr,
                nFilterIndex = 1,
                lpstrFile = filePtr,
                nMaxFile = maxChars,
                lpstrTitle = titlePtr,
                Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST | OFN_NOCHANGEDIR | OFN_EXPLORER
            };

            if (!GetOpenFileNameW(ref ofn)) return null;
            return Marshal.PtrToStringUni(filePtr);
        }
        finally
        {
            Marshal.FreeHGlobal(filterPtr);
            Marshal.FreeHGlobal(filePtr);
            Marshal.FreeHGlobal(titlePtr);
        }
    }

    private static string ReadProfileFileSmart(string filePath)
    {
        byte[] raw = File.ReadAllBytes(filePath);
        if (raw.Length == 0) return string.Empty;

        string decoded;
        if (raw.Length >= 3 && raw[0] == 0xEF && raw[1] == 0xBB && raw[2] == 0xBF)
        {
            decoded = Encoding.UTF8.GetString(raw, 3, raw.Length - 3);
        }
        else if (raw.Length >= 2 && raw[0] == 0xFF && raw[1] == 0xFE)
        {
            decoded = Encoding.Unicode.GetString(raw, 2, raw.Length - 2);
        }
        else if (raw.Length >= 2 && raw[0] == 0xFE && raw[1] == 0xFF)
        {
            decoded = Encoding.BigEndianUnicode.GetString(raw, 2, raw.Length - 2);
        }
        else
        {
            try
            {
                var strictUtf8 = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);
                decoded = strictUtf8.GetString(raw);
            }
            catch (DecoderFallbackException)
            {
                decoded = Encoding.GetEncoding(54936).GetString(raw); // GB18030 / GBK superset
            }
        }
        return NormalizeAndMaybeDecodeProfileText(decoded);
    }

    private static string NormalizeAndMaybeDecodeProfileText(string input)
    {
        string normalized = AppStateStore.NormalizeNewlines(input);
        string trimmed = normalized.Trim();
        if (trimmed.Length > 20 &&
            !trimmed.Contains("://", StringComparison.Ordinal) &&
            !trimmed.Contains("proxies:", StringComparison.Ordinal) &&
            !trimmed.Contains("[Proxy]", StringComparison.OrdinalIgnoreCase))
        {
            // Support both single-line AND MIME multi-line wrapped Base64 subscription payloads
            var compactSb = new StringBuilder(trimmed.Length);
            bool allBase64Chars = true;
            foreach (char c in trimmed)
            {
                if (c == '\r' || c == '\n' || c == ' ' || c == '\t') continue;
                if (char.IsLetterOrDigit(c) || c == '+' || c == '/' || c == '=' || c == '-' || c == '_')
                {
                    compactSb.Append(c == '-' ? '+' : (c == '_' ? '/' : c));
                }
                else
                {
                    allBase64Chars = false;
                    break;
                }
            }
            if (allBase64Chars && compactSb.Length >= 20)
            {
                try
                {
                    while (compactSb.Length % 4 != 0) compactSb.Append('=');
                    byte[] bytes = Convert.FromBase64String(compactSb.ToString());
                    string candidate = AppStateStore.NormalizeNewlines(Encoding.UTF8.GetString(bytes));
                    if (candidate.Contains("://", StringComparison.Ordinal) ||
                        candidate.Contains("proxies:", StringComparison.Ordinal) ||
                        candidate.Contains("[Proxy]", StringComparison.OrdinalIgnoreCase))
                    {
                        return candidate;
                    }
                }
                catch
                {
                    // Keep original text when not Base64 subscription payload
                }
            }
        }
        return normalized;
    }

    private async Task<ManagedProfileEntry> FetchAndStoreSubscriptionByUrlAsync(
        string? customName, string url, bool activateAfterFetch)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out Uri? uri) ||
            (uri.Scheme != Uri.UriSchemeHttps && uri.Scheme != Uri.UriSchemeHttp))
        {
            throw new ArgumentException("请输入有效的 HTTP/HTTPS 订阅链接");
        }

        string? raw = await AppStateStore.DownloadTextSmartAsync(_engine, SubHttp, uri);
        if (string.IsNullOrWhiteSpace(raw))
        {
            throw new InvalidOperationException("远程订阅返回内容为空或网络无法访问");
        }

        string text = NormalizeAndMaybeDecodeProfileText(raw);
        if (activateAfterFetch)
        {
            ProfileEditorBox.Text = text;
            _engine.LoadProfileText(text);
            _stateStore.LoadCachedProvidersAndRuleSetsIntoEngine(_engine);
            RestoreSavedPolicySelections();
        }
        var snap = _engine.GetStatusSnapshot();
        var saved = _stateStore.AddOrUpdateRemoteSubscription(
            customName, url, text, snap.NodeCount, snap.Groups.Count, setActive: activateAfterFetch);

        string syncNote = $"上次同步：{DateTime.Now:yyyy-MM-dd HH:mm:ss}（{saved.Name}）";
        SubSyncStatusLabel.Text = syncNote;
        _stateStore.Settings.LastSubSyncText = syncNote;
        _stateStore.SaveSettings();
        return saved;
    }

    private async void OnFetchSubscriptionClick(object sender, RoutedEventArgs e)
    {
        try
        {
            string url = SubUrlInput.Text.Trim();
            string customName = SubNameInput?.Text.Trim() ?? "";
            var saved = await FetchAndStoreSubscriptionByUrlAsync(customName, url, activateAfterFetch: true);
            if (SubNameInput != null) SubNameInput.Text = "";
            RefreshAllProfileViews();

            int rsCount = await _stateStore.RefreshRemoteRuleSetsAsync(_engine, SubHttp);
            RestoreSavedPolicySelections();
            RefreshAllProfileViews();
            var snap = _engine.GetStatusSnapshot();
            ShowBanner(InfoBarSeverity.Success,
                $"订阅「{saved.Name}」已添加并启用：{snap.NodeCount} 个节点 · {snap.Groups.Count} 个策略组 · 规则集已同步 {rsCount}/{snap.RuleSetCount}");
        }
        catch (Exception ex)
        {
            ShowBanner(InfoBarSeverity.Error, $"拉取订阅失败：{ex.Message}");
        }
    }

    private async void OnUpdateSingleSubscriptionClick(object sender, RoutedEventArgs e)
    {
        if (sender is not Button { Tag: string entryId }) return;
        var entry = _stateStore.GetRemoteSubscriptions().FirstOrDefault(x => x.Id == entryId);
        if (entry == null) return;

        try
        {
            bool wasActive = entry.IsActive;
            var updated = await FetchAndStoreSubscriptionByUrlAsync(entry.Name, entry.Source, activateAfterFetch: true);
            _ = await _stateStore.RefreshRemoteRuleSetsAsync(_engine, SubHttp);
            RestoreSavedPolicySelections();
            RefreshAllProfileViews();
            var snap = _engine.GetStatusSnapshot();
            ShowBanner(InfoBarSeverity.Success,
                $"已更新订阅「{updated.Name}」{(wasActive ? "" : "并切换为当前使用")}：{snap.NodeCount} 个节点 · {snap.Groups.Count} 个策略组");
        }
        catch (Exception ex)
        {
            ShowBanner(InfoBarSeverity.Error, $"更新订阅「{entry.Name}」失败：{ex.Message}");
        }
    }

    private async void OnUpdateAllSubscriptionsClick(object sender, RoutedEventArgs e)
    {
        var subs = _stateStore.GetRemoteSubscriptions();
        if (subs.Count == 0)
        {
            ShowBanner(InfoBarSeverity.Informational, "当前列表暂无远程订阅可更新");
            return;
        }
        int ok = 0;
        string activeId = _stateStore.Settings.ActiveProfileEntryId;
        foreach (var sub in subs)
        {
            try
            {
                await FetchAndStoreSubscriptionByUrlAsync(sub.Name, sub.Source, activateAfterFetch: sub.Id == activeId);
                ok++;
            }
            catch { }
        }
        _ = await _stateStore.RefreshRemoteRuleSetsAsync(_engine, SubHttp);
        RestoreSavedPolicySelections();
        RefreshAllProfileViews();
        ShowBanner(InfoBarSeverity.Success, $"已完成全部订阅批量更新：成功 {ok} / {subs.Count} 个");
    }

    private void OnActivateManagedProfileClick(object sender, RoutedEventArgs e)
    {
        if (sender is not Button { Tag: string entryId }) return;
        try
        {
            string? content = _stateStore.ActivateManagedProfile(entryId);
            if (string.IsNullOrWhiteSpace(content))
            {
                ShowBanner(InfoBarSeverity.Warning, "目标配置文件缓存不存在，请重新拉取或导入");
                return;
            }
            ProfileEditorBox.Text = content;
            _engine.LoadProfileText(content);
            _stateStore.LoadCachedProvidersAndRuleSetsIntoEngine(_engine);
            RestoreSavedPolicySelections();
            RefreshAllProfileViews();
            var active = _stateStore.GetActiveManagedProfile();
            var snap = _engine.GetStatusSnapshot();
            ShowBanner(InfoBarSeverity.Success,
                $"已切换启用「{active?.Name ?? entryId}」：{snap.NodeCount} 个节点 · {snap.Groups.Count} 个策略组");
        }
        catch (Exception ex)
        {
            ShowBanner(InfoBarSeverity.Error, $"切换档案失败：{ex.Message}");
        }
    }

    private void OnDeleteManagedProfileClick(object sender, RoutedEventArgs e)
    {
        if (sender is not Button { Tag: string entryId }) return;
        bool wasActive = _stateStore.Settings.ActiveProfileEntryId == entryId;
        if (!_stateStore.DeleteManagedProfile(entryId, out var nextEntry, out string? nextContent))
            return;

        if (wasActive)
        {
            string fallback = !string.IsNullOrWhiteSpace(nextContent) ? nextContent : DefaultStarterProfile;
            ProfileEditorBox.Text = fallback;
            try
            {
                _engine.LoadProfileText(fallback);
                if (nextEntry == null) _stateStore.SaveActiveProfileText(fallback);
                _stateStore.LoadCachedProvidersAndRuleSetsIntoEngine(_engine);
                RestoreSavedPolicySelections();
            }
            catch { }
            ShowBanner(InfoBarSeverity.Informational,
                nextEntry != null ? $"已删除原配置，自动切换至「{nextEntry.Name}」" : "已删除配置并恢复为默认初始直连档案");
        }
        else
        {
            ShowBanner(InfoBarSeverity.Informational, "已从配置管理列表中删除该条目");
        }
        RefreshAllProfileViews();
    }

    private async void OnRefreshRuleSetsClick(object sender, RoutedEventArgs e)
    {
        int updated = await _stateStore.RefreshRemoteRuleSetsAsync(_engine, SubHttp);
        RestoreSavedPolicySelections();
        RefreshAllProfileViews();
        var snap = _engine.GetStatusSnapshot();
        ShowBanner(InfoBarSeverity.Success,
            $"已完成外部源与规则集刷新：本次更新 {updated} 项，当前生效 {snap.LoadedRuleSetCount}/{snap.RuleSetCount}（共 {snap.RuleCount} 条展开规则）");
    }

    private void OnRunDiagnosticsClick(object sender, RoutedEventArgs e)
    {
        var report = _engine.RunDiagnostics();
        RenderDiagnosticsReport(report);
        ShowBanner(
            report.Ok ? InfoBarSeverity.Success : InfoBarSeverity.Warning,
            report.Ok ? "五阶段网络与密码学协议栈自检全部通过" : "网络诊断存在需关注项，请查看阶段详情");
    }

    private void RenderDiagnosticsReport(DiagnosticsReportDto report)
    {
        if (DiagnosticsCardsPanel == null || DiagnosticsOutputBox == null) return;

        var panelBrush = ResBrush("HajimiPanelBrush", Color.FromArgb(255, 26, 31, 34));
        var borderBrush = ResBrush("HajimiBorderBrush", Color.FromArgb(40, 236, 253, 245));
        var accentBrush = ResBrush("HajimiAccentBrush", Color.FromArgb(255, 46, 209, 156));
        var accentSoftBrush = ResBrush("HajimiAccentSoftBrush", Color.FromArgb(40, 46, 209, 156));
        var accentTextBrush = ResBrush("HajimiAccentTextBrush", Color.FromArgb(255, 52, 232, 184));
        var priTextBrush = ResBrush("HajimiTextPrimaryBrush", Color.FromArgb(255, 236, 253, 245));
        var secTextBrush = ResBrush("HajimiTextSecondaryBrush", Color.FromArgb(255, 141, 163, 153));
        var warnBrush = new SolidColorBrush(Color.FromArgb(255, 245, 158, 11));

        DiagnosticsCardsPanel.Children.Clear();
        var sb = new StringBuilder();
        sb.AppendLine($"[{DateTime.Now:HH:mm:ss}] 总体健康评估: {(report.Ok ? "PASS (全部正常)" : "WARN (需检查)")}");

        foreach (var s in report.Stages)
        {
            bool healthy = string.Equals(s.Status, "healthy", StringComparison.OrdinalIgnoreCase);
            string detail = s.Stage switch
            {
                3 => $"DNS 查询 {s.Queries} 次 · Fake-IP 命中 {s.FakeIpHits} 次",
                4 => $"自检耗时 {s.SelfTestUs} µs · AEAD / WireGuard / SPSC 零拷贝验证通过",
                5 => s.HttpPort > 0 ? $"HTTP 127.0.0.1:{s.HttpPort} · SOCKS5 127.0.0.1:{s.SocksPort}" : "入站监听待启动",
                _ => $"P50 = {s.P50Ms:F1} ms  ·  P95 = {s.P95Ms:F1} ms"
            };
            sb.AppendLine($"  阶段 {s.Stage} [{s.Status.ToUpperInvariant()}] {s.Name} — {detail}");

            var row = new Grid { ColumnSpacing = 14 };
            row.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
            row.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            row.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

            var numBadge = new Border
            {
                Width = 32,
                Height = 32,
                CornerRadius = new CornerRadius(8),
                Background = accentSoftBrush,
                VerticalAlignment = VerticalAlignment.Center,
                Child = new TextBlock
                {
                    Text = $"0{s.Stage}",
                    FontWeight = Microsoft.UI.Text.FontWeights.Bold,
                    Foreground = accentTextBrush,
                    HorizontalAlignment = HorizontalAlignment.Center,
                    VerticalAlignment = VerticalAlignment.Center
                }
            };
            row.Children.Add(numBadge);

            var midStack = new StackPanel { Spacing = 2, VerticalAlignment = VerticalAlignment.Center };
            midStack.Children.Add(new TextBlock
            {
                Text = s.Name,
                FontSize = 13.5,
                FontWeight = Microsoft.UI.Text.FontWeights.SemiBold,
                Foreground = priTextBrush
            });
            midStack.Children.Add(new TextBlock
            {
                Text = detail,
                FontSize = 11.5,
                Foreground = secTextBrush
            });
            Grid.SetColumn(midStack, 1);
            row.Children.Add(midStack);

            var statusPill = new Border
            {
                Background = accentSoftBrush,
                CornerRadius = new CornerRadius(6),
                Padding = new Thickness(10, 4, 10, 4),
                VerticalAlignment = VerticalAlignment.Center,
                Child = new TextBlock
                {
                    Text = healthy ? "● HEALTHY" : $"● {s.Status.ToUpperInvariant()}",
                    FontSize = 11,
                    FontWeight = Microsoft.UI.Text.FontWeights.Bold,
                    Foreground = healthy ? accentBrush : warnBrush
                }
            };
            Grid.SetColumn(statusPill, 2);
            row.Children.Add(statusPill);

            DiagnosticsCardsPanel.Children.Add(new Border
            {
                Background = panelBrush,
                BorderBrush = borderBrush,
                BorderThickness = new Thickness(1),
                CornerRadius = new CornerRadius(11),
                Padding = new Thickness(16, 12, 16, 12),
                Child = row
            });
        }

        DiagnosticsOutputBox.Text = sb.ToString();
    }

    private void OnThemeSearchTextChanged(object sender, TextChangedEventArgs e)
    {
        string q = ThemeSearchBox?.Text.Trim() ?? "";
        if (string.IsNullOrEmpty(q))
        {
            ThemeGalleryList.ItemsSource = _themeEngine.Themes;
            return;
        }
        ThemeGalleryList.ItemsSource = _themeEngine.Themes.Where(t =>
            t.Name.Contains(q, StringComparison.OrdinalIgnoreCase) ||
            t.EnglishName.Contains(q, StringComparison.OrdinalIgnoreCase) ||
            t.Category.Contains(q, StringComparison.OrdinalIgnoreCase) ||
            t.Code.Contains(q, StringComparison.OrdinalIgnoreCase)).ToList();
    }

    private async void OnImportRemoteThemeClick(object sender, RoutedEventArgs e)
    {
        try
        {
            int added = await _themeEngine.ImportFromHttpsUrlAsync(ThemeUrlBox.Text.Trim());
            ThemeGalleryList.ItemsSource = null;
            ThemeGalleryList.ItemsSource = _themeEngine.Themes;
            ShowBanner(InfoBarSeverity.Success, $"成功导入 {added} 款远程主题配置");
        }
        catch (Exception ex)
        {
            ShowBanner(InfoBarSeverity.Error, ex.Message);
        }
    }

    private void OnImportLocalThemeFileClick(object sender, RoutedEventArgs e)
    {
        string? path = PickFileWin32(
            "Hajimi 主题文件 (*.json)\0*.json\0所有文件 (*.*)\0*.*\0\0",
            "选择本地 .hajimitheme.json 主题包");
        if (string.IsNullOrEmpty(path)) return;

        try
        {
            int added = _themeEngine.ImportFromFile(path);
            ThemeGalleryList.ItemsSource = null;
            ThemeGalleryList.ItemsSource = _themeEngine.Themes;
            ShowBanner(InfoBarSeverity.Success, $"成功导入 {added} 款本地主题配置");
        }
        catch (Exception ex)
        {
            ShowBanner(InfoBarSeverity.Error, ex.Message);
        }
    }

    private void OnThemeSelected(object sender, SelectionChangedEventArgs e)
    {
        if (ThemeGalleryList.SelectedItem is HajimiThemeTokenSet selected)
        {
            _themeEngine.ApplyTheme(selected.Id, RootGrid, Application.Current.Resources);
        }
    }

    private void ShowBanner(InfoBarSeverity severity, string message)
    {
        StatusBanner.Severity = severity;
        StatusBanner.Message = message;
        StatusBanner.IsOpen = true;
    }

    private async void OnWindowClosed(object sender, WindowEventArgs args)
    {
        _telemetryTimer.Stop();
        _subAutoRefreshTimer.Stop();
        _networkWatcher.Dispose();
        if (SysProxyToggle.IsOn)
        {
            _engine.DisableSystemProxy(out _);
        }
        if (_helperClient.IsEnhancedModeActive)
        {
            await _helperClient.DisableEnhancedModeAsync(_engine);
        }
        _trayPopover?.ClosePermanently();
        _helperClient.Dispose();
        _trayService.Dispose();
        _engine.Dispose();
    }
}
