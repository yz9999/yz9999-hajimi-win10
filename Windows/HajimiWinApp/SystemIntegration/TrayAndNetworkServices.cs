using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using HajimiWinApp.Interop;
using Microsoft.Win32;
using Windows.ApplicationModel.DataTransfer;

namespace HajimiWinApp.SystemIntegration;

public enum TrayVisualState
{
    DirectIdle = 0,
    SystemProxyActive = 1,
    EnhancedTunActive = 2
}

public enum TrayMenuAction : uint
{
    ShowWindow = 1001,
    ModeRule = 1002,
    ModeGlobal = 1003,
    ModeDirect = 1004,
    ToggleSystemProxy = 1005,
    ToggleEnhancedTun = 1006,
    ProbeAllNodes = 1007,
    RefreshSubscription = 1008,
    DisconnectAll = 1009,
    FlushDns = 1010,
    ToggleAutoStart = 1011,
    ExitApp = 1012
}

/// Native Win32 System Tray (`Shell_NotifyIconW`) + `ComCtl32` `SetWindowSubclass` WndProc hook
/// (including `WM_SYSCOMMAND` `SC_MINIMIZE` interception) + Rich Win32 Context Menu.
public sealed partial class TrayIconService : IDisposable
{
    private const uint NimAdd = 0x00000000;
    private const uint NimModify = 0x00000001;
    private const uint NimDelete = 0x00000002;
    private const uint NifMessage = 0x00000001;
    private const uint NifIcon = 0x00000002;
    private const uint NifTip = 0x00000004;
    public const uint WmTrayCallback = 0x8000 + 0x68;

    private const uint WmSysCommand = 0x0112;
    private const nuint ScMinimize = 0xF020;

    private const uint WmLButtonUp = 0x0202;
    private const uint WmLButtonDblClk = 0x0203;
    private const uint WmRButtonUp = 0x0205;
    private const uint WmContextMenu = 0x007B;

    private const uint MfString = 0x00000000;
    private const uint MfGrayed = 0x00000001;
    private const uint MfChecked = 0x00000008;
    private const uint MfPopup = 0x00000010;
    private const uint MfSeparator = 0x00000800;
    private const uint TpmRightButton = 0x0002;
    private const uint TpmNonotify = 0x0080;
    private const uint TpmReturnCmd = 0x0100;

    private const int SwHide = 0;
    private const int SwShow = 5;
    private const int SwRestore = 9;

    private delegate IntPtr SubclassProcDelegate(
        IntPtr hWnd, uint uMsg, IntPtr wParam, IntPtr lParam, nuint uIdSubclass, nuint dwRefData);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private unsafe struct NotifyIconDataW
    {
        public uint cbSize;
        public IntPtr hWnd;
        public uint uID;
        public uint uFlags;
        public uint uCallbackMessage;
        public IntPtr hIcon;
        public fixed char szTip[128];
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct Win32Point
    {
        public int X;
        public int Y;
    }

    [DllImport("shell32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern bool Shell_NotifyIconW(uint dwMessage, ref NotifyIconDataW lpData);

    [DllImport("comctl32.dll", ExactSpelling = true)]
    private static extern bool SetWindowSubclass(
        IntPtr hWnd, SubclassProcDelegate pfnSubclass, nuint uIdSubclass, nuint dwRefData);

    [DllImport("comctl32.dll", ExactSpelling = true)]
    private static extern bool RemoveWindowSubclass(
        IntPtr hWnd, SubclassProcDelegate pfnSubclass, nuint uIdSubclass);

    [DllImport("comctl32.dll", ExactSpelling = true)]
    private static extern IntPtr DefSubclassProc(
        IntPtr hWnd, uint uMsg, IntPtr wParam, IntPtr lParam);

    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr LoadIconW(IntPtr hInstance, IntPtr lpIconName);

    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr LoadImageW(IntPtr hInst, string lpszName, uint uType, int cx, int cy, uint fuLoad);

    [DllImport("user32.dll", ExactSpelling = true)]
    private static extern IntPtr CreatePopupMenu();

    [DllImport("user32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern bool AppendMenuW(IntPtr hMenu, uint uFlags, nuint uIDNewItem, string? lpNewItem);

    [DllImport("user32.dll", ExactSpelling = true)]
    private static extern bool DestroyMenu(IntPtr hMenu);

    [DllImport("user32.dll", ExactSpelling = true)]
    private static extern bool GetCursorPos(out Win32Point lpPoint);

    [DllImport("user32.dll", ExactSpelling = true)]
    private static extern uint TrackPopupMenuEx(
        IntPtr hMenu, uint fuFlags, int x, int y, IntPtr hwnd, IntPtr lptpm);

    [DllImport("user32.dll", ExactSpelling = true)]
    private static extern bool SetForegroundWindow(IntPtr hWnd);

    [DllImport("user32.dll", ExactSpelling = true)]
    private static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);

    private IntPtr _hwnd;
    private bool _added;
    private bool _subclassed;
    private string _latestRateSummary = "↓ 0 B/s  ↑ 0 B/s";
    private readonly SubclassProcDelegate _subclassDelegate;

    public OutboundRoutingMode CurrentMode { get; set; } = OutboundRoutingMode.Rule;
    public bool IsSystemProxyEnabled { get; set; }
    public bool IsEnhancedTunEnabled { get; set; }
    public bool MinimizeToTrayOnMinimize { get; set; } = true;
    public string ActiveProfileTitle { get; set; } = "默认配置";
    public string LatestRateSummary => _latestRateSummary;
    public Func<EngineStatusSnapshot>? SnapshotProvider { get; set; }

    public event Action? TrayPopoverToggleRequested;
    public event Action<TrayMenuAction>? MenuActionRequested;
    public event Action<string, string>? PolicyGroupSelectionRequested;
    public event Action<string>? GlobalNodeSelectionRequested;

    public TrayIconService()
    {
        _subclassDelegate = OnWindowSubclassedMessage;
    }

    public unsafe void Initialize(IntPtr windowHandle)
    {
        _hwnd = windowHandle;
        if (_hwnd == IntPtr.Zero) return;

        var nid = new NotifyIconDataW
        {
            cbSize = (uint)sizeof(NotifyIconDataW),
            hWnd = _hwnd,
            uID = 1,
            uFlags = NifMessage | NifIcon | NifTip,
            uCallbackMessage = WmTrayCallback,
            hIcon = LoadTrayIconHandle()
        };
        WriteTip(ref nid, "哈基米 (Hajimi) · 运行中");
        _added = Shell_NotifyIconW(NimAdd, ref nid);
        _subclassed = SetWindowSubclass(_hwnd, _subclassDelegate, 0x484Au, 0);
    }

    public void ShowMainWindow()
    {
        if (_hwnd == IntPtr.Zero) return;
        ShowWindow(_hwnd, SwRestore);
        ShowWindow(_hwnd, SwShow);
        SetForegroundWindow(_hwnd);
    }

    public void HideMainWindow()
    {
        if (_hwnd == IntPtr.Zero) return;
        ShowWindow(_hwnd, SwHide);
    }

    private IntPtr OnWindowSubclassedMessage(
        IntPtr hWnd, uint uMsg, IntPtr wParam, IntPtr lParam, nuint uIdSubclass, nuint dwRefData)
    {
        // Intercept standard Win32 Minimize button (`─`) when MinimizeToTrayOnMinimize is active
        if (uMsg == WmSysCommand && ((nuint)wParam.ToInt64() & 0xFFF0u) == ScMinimize && MinimizeToTrayOnMinimize)
        {
            HideMainWindow();
            return IntPtr.Zero;
        }

        if (uMsg == WmTrayCallback)
        {
            uint mouseMsg = (uint)(lParam.ToInt64() & 0xFFFF);
            if (mouseMsg == WmLButtonDblClk)
            {
                MenuActionRequested?.Invoke(TrayMenuAction.ShowWindow);
                return IntPtr.Zero;
            }
            if (mouseMsg == WmLButtonUp)
            {
                if (TrayPopoverToggleRequested != null)
                {
                    TrayPopoverToggleRequested.Invoke();
                }
                else
                {
                    MenuActionRequested?.Invoke(TrayMenuAction.ShowWindow);
                }
                return IntPtr.Zero;
            }
            if (mouseMsg == WmRButtonUp || mouseMsg == WmContextMenu)
            {
                ShowNativePopupMenu();
                return IntPtr.Zero;
            }
        }
        return DefSubclassProc(hWnd, uMsg, wParam, lParam);
    }

    private void ShowNativePopupMenu()
    {
        if (_hwnd == IntPtr.Zero) return;
        IntPtr hMenu = CreatePopupMenu();
        if (hMenu == IntPtr.Zero) return;

        var dynamicCommands = new Dictionary<uint, Action>();
        uint nextDynamicId = 2000;

        try
        {
            AppendMenuW(hMenu, MfString | MfGrayed, 0, $"Hajimi · {ActiveProfileTitle} ({_latestRateSummary})");
            AppendMenuW(hMenu, MfString, (nuint)TrayMenuAction.ShowWindow, "打开哈基米主窗口（左键单击托盘可开快捷面板）");
            AppendMenuW(hMenu, MfSeparator, 0, null);

            AppendMenuW(hMenu, MfString | (CurrentMode == OutboundRoutingMode.Rule ? MfChecked : 0),
                (nuint)TrayMenuAction.ModeRule, "出站模式：规则分流 (Rule)");
            AppendMenuW(hMenu, MfString | (CurrentMode == OutboundRoutingMode.Global ? MfChecked : 0),
                (nuint)TrayMenuAction.ModeGlobal, "出站模式：全局代理 (Global)");
            AppendMenuW(hMenu, MfString | (CurrentMode == OutboundRoutingMode.Direct ? MfChecked : 0),
                (nuint)TrayMenuAction.ModeDirect, "出站模式：全局直连 (Direct)");

            var snap = SnapshotProvider?.Invoke();
            if (snap != null)
            {
                if (CurrentMode == OutboundRoutingMode.Rule && snap.Groups.Count > 0)
                {
                    IntPtr hGroupsRoot = CreatePopupMenu();
                    if (hGroupsRoot != IntPtr.Zero)
                    {
                        foreach (var g in snap.Groups)
                        {
                            IntPtr hSingleGroup = CreatePopupMenu();
                            if (hSingleGroup == IntPtr.Zero) continue;
                            string capturedG = g.Name;
                            foreach (string m in g.Members)
                            {
                                uint cmdId = nextDynamicId++;
                                string capturedM = m;
                                bool isSel = string.Equals(m, g.Selected, StringComparison.Ordinal);
                                string rttNote = snap.NodeLatencies.TryGetValue(m, out int rtt) && rtt >= 0 ? $"	{rtt} ms" : "";
                                AppendMenuW(hSingleGroup, MfString | (isSel ? MfChecked : 0), cmdId, $"{m}{rttNote}");
                                dynamicCommands[cmdId] = () => PolicyGroupSelectionRequested?.Invoke(capturedG, capturedM);
                            }
                            AppendMenuW(hGroupsRoot, MfPopup, (nuint)hSingleGroup.ToInt64(), $"{g.Name}  [{g.Selected}]");
                        }
                        AppendMenuW(hMenu, MfSeparator, 0, null);
                        AppendMenuW(hMenu, MfPopup, (nuint)hGroupsRoot.ToInt64(), $"🧭 策略组分流配置 ({snap.Groups.Count} 组)");
                    }
                }
                else if (CurrentMode == OutboundRoutingMode.Global && snap.Nodes.Count > 0)
                {
                    IntPtr hGlobalNodes = CreatePopupMenu();
                    if (hGlobalNodes != IntPtr.Zero)
                    {
                        string selGlobal = string.IsNullOrEmpty(snap.GlobalSelectedNode) ? "__AUTO_FASTEST__" : snap.GlobalSelectedNode;
                        uint autoId = nextDynamicId++;
                        AppendMenuW(
                            hGlobalNodes,
                            MfString | (selGlobal == "__AUTO_FASTEST__" ? MfChecked : 0),
                            autoId,
                            $"⚡ 自动最低延迟优选 ({snap.EffectiveGlobalNode})");
                        dynamicCommands[autoId] = () => GlobalNodeSelectionRequested?.Invoke("__AUTO_FASTEST__");
                        AppendMenuW(hGlobalNodes, MfSeparator, 0, null);

                        foreach (var nd in snap.Nodes)
                        {
                            uint cmdId = nextDynamicId++;
                            string capturedNode = nd.Name;
                            bool isSel = string.Equals(selGlobal, nd.Name, StringComparison.Ordinal);
                            string rttNote = snap.NodeLatencies.TryGetValue(nd.Name, out int rtt)
                                ? (rtt >= 0 ? $"	{rtt} ms" : "	超时")
                                : "";
                            AppendMenuW(hGlobalNodes, MfString | (isSel ? MfChecked : 0), cmdId, $"{nd.Name} [{nd.Type.ToUpperInvariant()}]{rttNote}");
                            dynamicCommands[cmdId] = () => GlobalNodeSelectionRequested?.Invoke(capturedNode);
                        }
                        AppendMenuW(hMenu, MfSeparator, 0, null);
                        AppendMenuW(hMenu, MfPopup, (nuint)hGlobalNodes.ToInt64(), $"🌐 全局节点选举 ({snap.EffectiveGlobalNode})");
                    }
                }
            }

            AppendMenuW(hMenu, MfSeparator, 0, null);
            AppendMenuW(hMenu, MfString | (IsSystemProxyEnabled ? MfChecked : 0),
                (nuint)TrayMenuAction.ToggleSystemProxy, "系统代理 (WinINet)");
            AppendMenuW(hMenu, MfString | (IsEnhancedTunEnabled ? MfChecked : 0),
                (nuint)TrayMenuAction.ToggleEnhancedTun, "TUN 增强模式 (Wintun + WFP)");

            AppendMenuW(hMenu, MfSeparator, 0, null);
            AppendMenuW(hMenu, MfString, (nuint)TrayMenuAction.ProbeAllNodes, "⚡ 一键并发测速全部节点");
            AppendMenuW(hMenu, MfString, (nuint)TrayMenuAction.RefreshSubscription, "↻ 更新远程订阅与规则集");
            AppendMenuW(hMenu, MfString, (nuint)TrayMenuAction.DisconnectAll, "一键断开全部活动连接");
            AppendMenuW(hMenu, MfString, (nuint)TrayMenuAction.FlushDns, "刷新 DNS 与 Fake-IP 缓存");

            AppendMenuW(hMenu, MfSeparator, 0, null);
            AppendMenuW(hMenu, MfString | (IsAutoStartEnabled() ? MfChecked : 0),
                (nuint)TrayMenuAction.ToggleAutoStart, "开机自动启动（静默驻留托盘）");
            AppendMenuW(hMenu, MfString, (nuint)TrayMenuAction.ExitApp, "彻底退出哈基米");

            GetCursorPos(out Win32Point pt);
            SetForegroundWindow(_hwnd);
            uint cmd = TrackPopupMenuEx(
                hMenu, TpmRightButton | TpmReturnCmd | TpmNonotify, pt.X, pt.Y, _hwnd, IntPtr.Zero);
            if (cmd != 0)
            {
                if (dynamicCommands.TryGetValue(cmd, out var dynAction))
                {
                    dynAction();
                }
                else
                {
                    MenuActionRequested?.Invoke((TrayMenuAction)cmd);
                }
            }
        }
        finally
        {
            DestroyMenu(hMenu);
        }
    }

    public unsafe void UpdateState(TrayVisualState state, string downRate, string upRate)
    {
        _latestRateSummary = $"↓{downRate} ↑{upRate}";
        if (!_added || _hwnd == IntPtr.Zero) return;
        string modeLabel = state switch
        {
            TrayVisualState.EnhancedTunActive => "增强模式 (TUN + WFP)",
            TrayVisualState.SystemProxyActive => "系统代理已开启",
            _ => "直连待机"
        };
        var nid = new NotifyIconDataW
        {
            cbSize = (uint)sizeof(NotifyIconDataW),
            hWnd = _hwnd,
            uID = 1,
            uFlags = NifTip
        };
        WriteTip(ref nid, $"哈基米 · {modeLabel} | {_latestRateSummary}");
        Shell_NotifyIconW(NimModify, ref nid);
    }

    public static void CopyTerminalProxyCommands(string shellKind, ushort httpPort, ushort socksPort)
    {
        string cmd = shellKind.ToLowerInvariant() switch
        {
            "cmd" => $"set http_proxy=http://127.0.0.1:{httpPort} & set https_proxy=http://127.0.0.1:{httpPort} & set all_proxy=socks5://127.0.0.1:{socksPort}",
            "bash" => $"export http_proxy=http://127.0.0.1:{httpPort} https_proxy=http://127.0.0.1:{httpPort} all_proxy=socks5h://127.0.0.1:{socksPort}",
            _ => $"$env:HTTP_PROXY=\"http://127.0.0.1:{httpPort}\"; $env:HTTPS_PROXY=\"http://127.0.0.1:{httpPort}\"; $env:ALL_PROXY=\"socks5://127.0.0.1:{socksPort}\""
        };
        var pkg = new DataPackage();
        pkg.SetText(cmd);
        Clipboard.SetContent(pkg);
    }

    public static bool IsAutoStartEnabled()
    {
        using var key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Run", writable: false);
        return key?.GetValue("Hajimi") is string val && !string.IsNullOrWhiteSpace(val);
    }

    public static void SetAutoStart(bool enabled)
    {
        using var key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Run", writable: true);
        if (key == null) return;
        if (enabled)
        {
            string exePath = Environment.ProcessPath ?? Path.Combine(AppContext.BaseDirectory, "Hajimi.exe");
            key.SetValue("Hajimi", $"\"{exePath}\" --minimized");
        }
        else
        {
            key.DeleteValue("Hajimi", throwOnMissingValue: false);
        }
    }

    private static IntPtr LoadTrayIconHandle()
    {
        string icoPath = Path.Combine(AppContext.BaseDirectory, "Assets", "Hajimi.ico");
        if (File.Exists(icoPath))
        {
            IntPtr hCustom = LoadImageW(IntPtr.Zero, icoPath, 1, 32, 32, 0x00000010);
            if (hCustom != IntPtr.Zero) return hCustom;
        }
        return LoadIconW(IntPtr.Zero, (IntPtr)32512);
    }

    private static unsafe void WriteTip(ref NotifyIconDataW nid, string text)
    {
        int maxLen = Math.Min(text.Length, 126);
        for (int i = 0; i < maxLen; i++) nid.szTip[i] = text[i];
        nid.szTip[maxLen] = '\0';
    }

    public unsafe void Dispose()
    {
        if (_subclassed && _hwnd != IntPtr.Zero)
        {
            RemoveWindowSubclass(_hwnd, _subclassDelegate, 0x484Au);
            _subclassed = false;
        }
        if (_added && _hwnd != IntPtr.Zero)
        {
            var nid = new NotifyIconDataW
            {
                cbSize = (uint)sizeof(NotifyIconDataW),
                hWnd = _hwnd,
                uID = 1
            };
            Shell_NotifyIconW(NimDelete, ref nid);
            _added = false;
        }
    }
}

public sealed class NetworkPowerWatcher : IDisposable
{
    private readonly Action<string?> _onNetworkRebindRequired;
    private CancellationTokenSource? _debounceCts;
    private readonly object _gate = new();

    public bool IsCaptivePortalSuspected { get; private set; }

    public NetworkPowerWatcher(Action<string?> onNetworkRebindRequired)
    {
        _onNetworkRebindRequired = onNetworkRebindRequired;
        NetworkChange.NetworkAddressChanged += OnNetworkChanged;
        NetworkChange.NetworkAvailabilityChanged += OnAvailabilityChanged;
    }

    public void NotifyModernStandbyResume() => ScheduleDebouncedRebind();

    private void OnNetworkChanged(object? sender, EventArgs e) => ScheduleDebouncedRebind();
    private void OnAvailabilityChanged(object? sender, NetworkAvailabilityEventArgs e) => ScheduleDebouncedRebind();

    private void ScheduleDebouncedRebind()
    {
        CancellationTokenSource cts;
        lock (_gate)
        {
            _debounceCts?.Cancel();
            _debounceCts?.Dispose();
            _debounceCts = new CancellationTokenSource();
            cts = _debounceCts;
        }

        _ = Task.Run(async () =>
        {
            try
            {
                await Task.Delay(400, cts.Token);
                string? activeNic = DetectPrimaryPhysicalNic(out bool localOnly);
                IsCaptivePortalSuspected = localOnly;
                _onNetworkRebindRequired(activeNic);
            }
            catch (OperationCanceledException) { }
        }, cts.Token);
    }

    public static string? DetectPrimaryPhysicalNic(out bool captivePortalSuspected)
    {
        captivePortalSuspected = false;
        foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (nic.OperationalStatus != OperationalStatus.Up) continue;
            if (nic.NetworkInterfaceType == NetworkInterfaceType.Loopback ||
                nic.Name.Contains("Hajimi", StringComparison.OrdinalIgnoreCase) ||
                nic.Description.Contains("Wintun", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }
            var ipProps = nic.GetIPProperties();
            if (ipProps.GatewayAddresses.Count > 0)
            {
                captivePortalSuspected = ipProps.DnsAddresses.Count == 0;
                return nic.Name;
            }
        }
        return null;
    }

    public void Dispose()
    {
        NetworkChange.NetworkAddressChanged -= OnNetworkChanged;
        NetworkChange.NetworkAvailabilityChanged -= OnAvailabilityChanged;
        lock (_gate)
        {
            _debounceCts?.Cancel();
            _debounceCts?.Dispose();
            _debounceCts = null;
        }
    }
}
