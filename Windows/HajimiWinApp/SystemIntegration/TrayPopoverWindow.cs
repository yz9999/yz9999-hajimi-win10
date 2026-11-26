using System.Runtime.InteropServices;
using HajimiWinApp.Interop;
using HajimiWinApp.Themes;
using Microsoft.UI;
using Microsoft.UI.Windowing;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Windows.Graphics;
using Windows.UI;
using WinRT.Interop;

namespace HajimiWinApp.SystemIntegration;

/// <summary>
/// macOS StatusBar-parity WinUI 3 Tray Popover Flyout Card (`TrayPopoverWindow`):
/// - Left-clicking the Windows system tray icon opens this borderless, rounded, Always-On-Top
///   themed card anchored directly above the taskbar tray area.
/// - Rule Mode (`Rule`): Displays every Policy Group with inline expandable node/sub-group picker.
/// - Global Mode (`Global`): Displays direct Leaf Proxy Node election list (`⚡ 自动最低延迟优选` + all nodes with RTT).
/// - Direct Mode (`Direct`): Displays compact Direct passthrough card.
/// </summary>
public sealed class TrayPopoverWindow : Window
{
    private const int SwHide = 0;
    private const int SwShow = 5;
    private const uint MonitorDefaultToNearest = 2;

    [StructLayout(LayoutKind.Sequential)]
    private struct Win32Point { public int X; public int Y; }

    [StructLayout(LayoutKind.Sequential)]
    private struct Win32Rect { public int Left; public int Top; public int Right; public int Bottom; }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private unsafe struct MonitorInfoW
    {
        public uint cbSize;
        public Win32Rect rcMonitor;
        public Win32Rect rcWork;
        public uint dwFlags;
    }

    [DllImport("user32.dll", ExactSpelling = true)]
    private static extern bool GetCursorPos(out Win32Point lpPoint);

    [DllImport("user32.dll", ExactSpelling = true)]
    private static extern IntPtr MonitorFromPoint(Win32Point pt, uint dwFlags);

    [DllImport("user32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern bool GetMonitorInfoW(IntPtr hMonitor, ref MonitorInfoW lpmi);

    [DllImport("user32.dll", ExactSpelling = true)]
    private static extern uint GetDpiForWindow(IntPtr hwnd);

    [DllImport("user32.dll", ExactSpelling = true)]
    private static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);

    [DllImport("user32.dll", ExactSpelling = true)]
    private static extern bool SetForegroundWindow(IntPtr hWnd);

    [DllImport("dwmapi.dll", ExactSpelling = true)]
    private static extern int DwmSetWindowAttribute(IntPtr hwnd, int dwAttribute, ref int pvAttribute, int cbAttribute);

    private readonly IntPtr _hwnd;
    private readonly AppWindow _appWindow;
    private readonly Border _outerCard;
    private readonly StackPanel _rootStack;

    private string? _expandedGroupName;
    private bool _isVisiblePopover;
    private bool _allowPermanentClose;

    public event Action<OutboundRoutingMode>? ModeSelected;
    public event Action<string, string>? PolicyGroupMemberSelected;
    public event Action<string>? GlobalNodeSelected;
    public event Action? ProbeNodesRequested;
    public event Action? ToggleEnhancedTunRequested;
    public event Action? ToggleSystemProxyRequested;
    public event Action? RefreshSubscriptionRequested;
    public event Action? OpenMainWindowRequested;
    public event Action? ExitAppRequested;

    public bool IsPopoverVisible => _isVisiblePopover;

    public TrayPopoverWindow()
    {
        _hwnd = WindowNative.GetWindowHandle(this);
        WindowId wndId = Win32Interop.GetWindowIdFromWindow(_hwnd);
        _appWindow = AppWindow.GetFromWindowId(wndId);
        _appWindow.IsShownInSwitchers = false;

        if (_appWindow.Presenter is OverlappedPresenter op)
        {
            op.SetBorderAndTitleBar(false, false);
            op.IsResizable = false;
            op.IsMaximizable = false;
            op.IsMinimizable = false;
            op.IsAlwaysOnTop = true;
        }

        try
        {
            int roundPref = 2; // DWMWCP_ROUND on Windows 11
            _ = DwmSetWindowAttribute(_hwnd, 33, ref roundPref, sizeof(int));
        }
        catch
        {
            // Windows 10 ignores DWM corner attribute gracefully
        }

        _rootStack = new StackPanel { Spacing = 10 };
        _outerCard = new Border
        {
            CornerRadius = new CornerRadius(14),
            BorderThickness = new Thickness(1.2),
            Padding = new Thickness(16, 14, 16, 14),
            Child = _rootStack
        };
        Content = _outerCard;

        Activated += (_, args) =>
        {
            if (args.WindowActivationState == WindowActivationState.Deactivated && _isVisiblePopover)
            {
                HidePopover();
            }
        };

        _appWindow.Closing += (_, args) =>
        {
            if (!_allowPermanentClose)
            {
                args.Cancel = true;
                HidePopover();
            }
        };
    }

    public void HidePopover()
    {
        _isVisiblePopover = false;
        if (_hwnd != IntPtr.Zero)
        {
            ShowWindow(_hwnd, SwHide);
        }
    }

    public void ClosePermanently()
    {
        _allowPermanentClose = true;
        _isVisiblePopover = false;
        try { Close(); } catch { }
    }

    public unsafe void ShowNearTrayAndRefresh(
        EngineStatusSnapshot snap,
        HajimiThemeTokenSet theme,
        OutboundRoutingMode mode,
        bool sysProxyOn,
        bool tunOn,
        string activeProfileTitle,
        string rateSummary)
    {
        RebuildContent(snap, theme, mode, sysProxyOn, tunOn, activeProfileTitle, rateSummary);

        uint dpi = GetDpiForWindow(_hwnd);
        double scale = dpi > 0 ? dpi / 96.0 : 1.0;
        int dipW = 386;
        int dipH = mode == OutboundRoutingMode.Direct ? 268 : 476;
        int physW = (int)Math.Round(dipW * scale);
        int physH = (int)Math.Round(dipH * scale);

        GetCursorPos(out Win32Point pt);
        IntPtr hMon = MonitorFromPoint(pt, MonitorDefaultToNearest);
        var mi = new MonitorInfoW { cbSize = (uint)sizeof(MonitorInfoW) };
        int x = pt.X - physW / 2;
        int y = pt.Y - physH - 12;

        if (hMon != IntPtr.Zero && GetMonitorInfoW(hMon, ref mi))
        {
            int margin = (int)Math.Round(10 * scale);
            x = Math.Clamp(x, mi.rcWork.Left + margin, Math.Max(mi.rcWork.Left + margin, mi.rcWork.Right - physW - margin));
            y = Math.Clamp(y, mi.rcWork.Top + margin, Math.Max(mi.rcWork.Top + margin, mi.rcWork.Bottom - physH - margin));
        }

        _appWindow.MoveAndResize(new RectInt32(x, y, physW, physH));
        _isVisiblePopover = true;
        ShowWindow(_hwnd, SwShow);
        SetForegroundWindow(_hwnd);
        Activate();
    }

    public void RefreshInPlaceIfVisible(
        EngineStatusSnapshot snap,
        HajimiThemeTokenSet theme,
        OutboundRoutingMode mode,
        bool sysProxyOn,
        bool tunOn,
        string activeProfileTitle,
        string rateSummary)
    {
        if (!_isVisiblePopover) return;
        RebuildContent(snap, theme, mode, sysProxyOn, tunOn, activeProfileTitle, rateSummary);
    }

    private void RebuildContent(
        EngineStatusSnapshot snap,
        HajimiThemeTokenSet theme,
        OutboundRoutingMode mode,
        bool sysProxyOn,
        bool tunOn,
        string activeProfileTitle,
        string rateSummary)
    {
        var panelColor = HajimiWinThemeEngine.ParseHexColor(theme.PanelHex, Color.FromArgb(255, 26, 31, 34));
        var wsColor = HajimiWinThemeEngine.ParseHexColor(theme.WorkspaceHex, Color.FromArgb(255, 15, 18, 20));
        var elevColor = HajimiWinThemeEngine.ParseHexColor(theme.ElevatedPanelHex, Color.FromArgb(255, 32, 38, 41));
        var accentColor = HajimiWinThemeEngine.ParseHexColor(theme.AccentHex, Color.FromArgb(255, 46, 209, 156));
        var accentTextColor = HajimiWinThemeEngine.ParseHexColor(theme.AccentTextHex, Color.FromArgb(255, 52, 232, 184));
        var priColor = HajimiWinThemeEngine.ParseHexColor(theme.TextPrimaryHex, Color.FromArgb(255, 236, 253, 245));
        var secColor = HajimiWinThemeEngine.ParseHexColor(theme.TextSecondaryHex, Color.FromArgb(255, 141, 163, 153));
        bool lightAccent = (0.299 * accentColor.R + 0.587 * accentColor.G + 0.114 * accentColor.B) > 138.0;
        var onAccentColor = lightAccent ? Color.FromArgb(255, 7, 19, 14) : Colors.White;

        var panelBrush = new SolidColorBrush(panelColor);
        var wsBrush = new SolidColorBrush(wsColor);
        var elevBrush = new SolidColorBrush(elevColor);
        var accentBrush = new SolidColorBrush(accentColor);
        var accentSoftBrush = new SolidColorBrush(Color.FromArgb(42, accentColor.R, accentColor.G, accentColor.B));
        var accentBorderBrush = new SolidColorBrush(Color.FromArgb(140, accentColor.R, accentColor.G, accentColor.B));
        var borderBrush = new SolidColorBrush(Color.FromArgb(38, priColor.R, priColor.G, priColor.B));
        var accentTextBrush = new SolidColorBrush(accentTextColor);
        var priBrush = new SolidColorBrush(priColor);
        var secBrush = new SolidColorBrush(secColor);
        var onAccentBrush = new SolidColorBrush(onAccentColor);
        var warnBrush = new SolidColorBrush(Color.FromArgb(255, 245, 158, 11));
        var dangerBrush = new SolidColorBrush(Color.FromArgb(255, 239, 68, 68));

        _outerCard.Background = panelBrush;
        _outerCard.BorderBrush = accentBorderBrush;
        _outerCard.CornerRadius = new CornerRadius(Math.Clamp(theme.CardCornerRadius, 10, 20));
        _rootStack.Children.Clear();

        // 1. Header: Brand Shield + Title + Subtitle + RTT Pill
        var hdrGrid = new Grid { ColumnSpacing = 10 };
        hdrGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        hdrGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        hdrGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

        var shieldBox = new Border
        {
            Width = 34,
            Height = 34,
            CornerRadius = new CornerRadius(9),
            Background = accentSoftBrush,
            BorderBrush = accentBorderBrush,
            BorderThickness = new Thickness(1),
            Child = new TextBlock
            {
                Text = "H",
                FontSize = 15,
                FontWeight = Microsoft.UI.Text.FontWeights.Bold,
                Foreground = accentTextBrush,
                HorizontalAlignment = HorizontalAlignment.Center,
                VerticalAlignment = VerticalAlignment.Center
            }
        };
        hdrGrid.Children.Add(shieldBox);

        string subtitle = tunOn && sysProxyOn
            ? $"Wintun 增强 + 系统代理 · {rateSummary}"
            : (tunOn ? $"Wintun 增强模式 · {rateSummary}" : (sysProxyOn ? $"系统代理已开启 · {rateSummary}" : $"本地监听 :7890 · {rateSummary}"));

        var titleCol = new StackPanel { Spacing = 1, VerticalAlignment = VerticalAlignment.Center };
        titleCol.Children.Add(new TextBlock
        {
            Text = snap.Running ? "哈基米托盘控制栏 · 运行中" : "哈基米托盘控制栏 · 待机",
            FontSize = 13.5,
            FontWeight = Microsoft.UI.Text.FontWeights.Bold,
            Foreground = priBrush,
            TextTrimming = TextTrimming.CharacterEllipsis
        });
        titleCol.Children.Add(new TextBlock
        {
            Text = subtitle,
            FontSize = 11,
            Foreground = secBrush,
            TextTrimming = TextTrimming.CharacterEllipsis
        });
        Grid.SetColumn(titleCol, 1);
        hdrGrid.Children.Add(titleCol);

        int activeRtt = ResolveActiveLatencyMs(snap, mode);
        string rttBadgeText = mode == OutboundRoutingMode.Direct
            ? "DIRECT"
            : (activeRtt >= 0 ? $"{activeRtt} ms" : "测速");
        var rttBtn = new Button
        {
            Content = rttBadgeText,
            FontSize = 11,
            FontWeight = Microsoft.UI.Text.FontWeights.Bold,
            Padding = new Thickness(10, 4, 10, 4),
            CornerRadius = new CornerRadius(999),
            Background = activeRtt >= 0 ? accentBrush : accentSoftBrush,
            Foreground = activeRtt >= 0 ? onAccentBrush : accentTextBrush,
            BorderThickness = new Thickness(0),
            VerticalAlignment = VerticalAlignment.Center
        };
        rttBtn.Click += (_, _) => ProbeNodesRequested?.Invoke();
        Grid.SetColumn(rttBtn, 2);
        hdrGrid.Children.Add(rttBtn);
        _rootStack.Children.Add(hdrGrid);

        // 2. Three-Segment Outbound Mode Switcher ("规则分流" | "全局代理" | "全局直连")
        var modeGrid = new Grid { ColumnSpacing = 6 };
        modeGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        modeGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        modeGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });

        (OutboundRoutingMode Mode, string Label)[] modes =
        [
            (OutboundRoutingMode.Rule, "规则分流"),
            (OutboundRoutingMode.Global, "全局代理"),
            (OutboundRoutingMode.Direct, "全局直连")
        ];
        for (int i = 0; i < modes.Length; i++)
        {
            var mSpec = modes[i];
            bool isCur = mode == mSpec.Mode;
            var mBtn = new Button
            {
                Content = mSpec.Label,
                HorizontalAlignment = HorizontalAlignment.Stretch,
                FontSize = 12,
                FontWeight = Microsoft.UI.Text.FontWeights.Bold,
                Padding = new Thickness(6, 6, 6, 6),
                CornerRadius = new CornerRadius(7),
                Background = isCur ? accentBrush : new SolidColorBrush(Colors.Transparent),
                Foreground = isCur ? onAccentBrush : priBrush,
                BorderThickness = new Thickness(0)
            };
            var capturedMode = mSpec.Mode;
            mBtn.Click += (_, _) => ModeSelected?.Invoke(capturedMode);
            Grid.SetColumn(mBtn, i);
            modeGrid.Children.Add(mBtn);
        }

        _rootStack.Children.Add(new Border
        {
            Background = wsBrush,
            BorderBrush = borderBrush,
            BorderThickness = new Thickness(1),
            CornerRadius = new CornerRadius(9),
            Padding = new Thickness(4),
            Child = modeGrid
        });

        // 3. Mode-Adaptive Center Body
        if (mode == OutboundRoutingMode.Direct)
        {
            var directStack = new StackPanel { Spacing = 4 };
            directStack.Children.Add(new TextBlock
            {
                Text = "● 全局直连模式已生效",
                FontSize = 12.5,
                FontWeight = Microsoft.UI.Text.FontWeights.Bold,
                Foreground = accentTextBrush
            });
            directStack.Children.Add(new TextBlock
            {
                Text = "所有流量绕过分流规则与代理节点，直接经由物理网卡连接目标服务器。",
                FontSize = 11.5,
                Foreground = secBrush,
                TextWrapping = TextWrapping.Wrap
            });
            _rootStack.Children.Add(new Border
            {
                Background = wsBrush,
                BorderBrush = borderBrush,
                BorderThickness = new Thickness(1),
                CornerRadius = new CornerRadius(10),
                Padding = new Thickness(12, 10, 12, 10),
                Child = directStack
            });
        }
        else if (mode == OutboundRoutingMode.Rule)
        {
            if (string.IsNullOrEmpty(_expandedGroupName) && snap.Groups.Count > 0)
            {
                _expandedGroupName = snap.Groups[0].Name;
            }

            var secHeader = BuildSectionHeader(
                $"🧭 策略组分流配置（共 {snap.Groups.Count} 组 · 点击展开）",
                "⚡ 全部测速",
                secBrush,
                accentTextBrush,
                () => ProbeNodesRequested?.Invoke());

            var listStack = new StackPanel { Spacing = 6 };
            var groupSet = new HashSet<string>(snap.Groups.Select(x => x.Name), StringComparer.Ordinal);

            foreach (var g in snap.Groups)
            {
                bool isExp = string.Equals(_expandedGroupName, g.Name, StringComparison.Ordinal);
                var gRowGrid = new Grid { ColumnSpacing = 8 };
                gRowGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
                gRowGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

                var gLeft = new StackPanel { Spacing = 1 };
                gLeft.Children.Add(new TextBlock
                {
                    Text = g.Name,
                    FontSize = 12,
                    FontWeight = Microsoft.UI.Text.FontWeights.Bold,
                    Foreground = priBrush,
                    TextTrimming = TextTrimming.CharacterEllipsis
                });
                gLeft.Children.Add(new TextBlock
                {
                    Text = $"{g.Kind.ToUpperInvariant()} · {g.Members.Count} 项",
                    FontSize = 10,
                    Foreground = secBrush
                });
                gRowGrid.Children.Add(gLeft);

                string rttSuffix = snap.NodeLatencies.TryGetValue(g.Selected, out int ms) && ms >= 0 ? $" · {ms}ms" : "";
                var gRight = new TextBlock
                {
                    Text = $"{g.Selected}{rttSuffix} {(isExp ? "▴" : "▾")}",
                    FontSize = 11.5,
                    FontWeight = Microsoft.UI.Text.FontWeights.SemiBold,
                    Foreground = accentTextBrush,
                    VerticalAlignment = VerticalAlignment.Center,
                    MaxWidth = 165,
                    TextTrimming = TextTrimming.CharacterEllipsis
                };
                Grid.SetColumn(gRight, 1);
                gRowGrid.Children.Add(gRight);

                var gHeaderBtn = new Button
                {
                    HorizontalAlignment = HorizontalAlignment.Stretch,
                    HorizontalContentAlignment = HorizontalAlignment.Stretch,
                    Padding = new Thickness(10, 6, 10, 6),
                    CornerRadius = new CornerRadius(8),
                    Background = isExp ? accentSoftBrush : elevBrush,
                    BorderBrush = isExp ? accentBorderBrush : borderBrush,
                    BorderThickness = new Thickness(1),
                    Content = gRowGrid
                };
                string capturedGName = g.Name;
                gHeaderBtn.Click += (_, _) =>
                {
                    _expandedGroupName = string.Equals(_expandedGroupName, capturedGName, StringComparison.Ordinal)
                        ? null : capturedGName;
                    RebuildContent(snap, theme, mode, sysProxyOn, tunOn, activeProfileTitle, rateSummary);
                };
                listStack.Children.Add(gHeaderBtn);

                if (isExp)
                {
                    var membersStack = new StackPanel { Spacing = 4, Margin = new Thickness(8, 0, 2, 2) };
                    foreach (string member in g.Members)
                    {
                        bool isSel = string.Equals(member, g.Selected, StringComparison.Ordinal);
                        string rttStr = groupSet.Contains(member)
                            ? "嵌套组"
                            : (string.Equals(member, "DIRECT", StringComparison.OrdinalIgnoreCase)
                                ? "直连"
                                : (snap.NodeLatencies.TryGetValue(member, out int mRtt)
                                    ? (mRtt >= 0 ? $"{mRtt} ms" : "超时")
                                    : ""));

                        var mGrid = new Grid { ColumnSpacing = 6 };
                        mGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
                        mGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
                        mGrid.Children.Add(new TextBlock
                        {
                            Text = $"{(isSel ? "●" : "○")} {member}",
                            FontSize = 11.5,
                            FontWeight = isSel ? Microsoft.UI.Text.FontWeights.Bold : Microsoft.UI.Text.FontWeights.Medium,
                            Foreground = isSel ? accentTextBrush : priBrush,
                            TextTrimming = TextTrimming.CharacterEllipsis
                        });
                        if (!string.IsNullOrEmpty(rttStr))
                        {
                            var rttBlock = new TextBlock
                            {
                                Text = rttStr,
                                FontSize = 10.5,
                                FontWeight = Microsoft.UI.Text.FontWeights.SemiBold,
                                Foreground = secBrush,
                                VerticalAlignment = VerticalAlignment.Center
                            };
                            Grid.SetColumn(rttBlock, 1);
                            mGrid.Children.Add(rttBlock);
                        }

                        var mBtn = new Button
                        {
                            HorizontalAlignment = HorizontalAlignment.Stretch,
                            HorizontalContentAlignment = HorizontalAlignment.Stretch,
                            Padding = new Thickness(10, 5, 10, 5),
                            CornerRadius = new CornerRadius(6),
                            Background = isSel ? accentSoftBrush : wsBrush,
                            BorderBrush = isSel ? accentBorderBrush : borderBrush,
                            BorderThickness = new Thickness(1),
                            Content = mGrid
                        };
                        string chosenM = member;
                        mBtn.Click += (_, _) => PolicyGroupMemberSelected?.Invoke(capturedGName, chosenM);
                        membersStack.Children.Add(mBtn);
                    }
                    listStack.Children.Add(membersStack);
                }
            }

            var boxInner = new StackPanel { Spacing = 6 };
            boxInner.Children.Add(secHeader);
            boxInner.Children.Add(new ScrollViewer
            {
                Height = 204,
                VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
                Content = listStack
            });
            _rootStack.Children.Add(new Border
            {
                Background = wsBrush,
                BorderBrush = borderBrush,
                BorderThickness = new Thickness(1),
                CornerRadius = new CornerRadius(10),
                Padding = new Thickness(8, 6, 8, 8),
                Child = boxInner
            });
        }
        else
        {
            // GLOBAL MODE: Strictly elect a single leaf proxy node (or Auto-Fastest), bypassing all policy groups!
            var secHeader = BuildSectionHeader(
                $"🌐 全局节点选举（共 {snap.Nodes.Count} 节点 · 绕过规则）",
                "⚡ 全节点测速",
                secBrush,
                accentTextBrush,
                () => ProbeNodesRequested?.Invoke());

            var nodeStack = new StackPanel { Spacing = 5 };
            string selectedGlobal = string.IsNullOrEmpty(snap.GlobalSelectedNode) ? "__AUTO_FASTEST__" : snap.GlobalSelectedNode;

            // Option 0: Auto-Fastest Leaf Node
            bool autoSelected = selectedGlobal == "__AUTO_FASTEST__";
            var autoGrid = new Grid { ColumnSpacing = 8 };
            autoGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            autoGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
            autoGrid.Children.Add(new TextBlock
            {
                Text = $"{(autoSelected ? "●" : "○")} ⚡ 自动最低延迟优选 ({snap.EffectiveGlobalNode})",
                FontSize = 11.5,
                FontWeight = autoSelected ? Microsoft.UI.Text.FontWeights.Bold : Microsoft.UI.Text.FontWeights.SemiBold,
                Foreground = autoSelected ? accentTextBrush : priBrush,
                TextTrimming = TextTrimming.CharacterEllipsis
            });
            var autoTag = new TextBlock
            {
                Text = "AUTO",
                FontSize = 10,
                FontWeight = Microsoft.UI.Text.FontWeights.Bold,
                Foreground = accentTextBrush,
                VerticalAlignment = VerticalAlignment.Center
            };
            Grid.SetColumn(autoTag, 1);
            autoGrid.Children.Add(autoTag);

            var autoBtn = new Button
            {
                HorizontalAlignment = HorizontalAlignment.Stretch,
                HorizontalContentAlignment = HorizontalAlignment.Stretch,
                Padding = new Thickness(10, 6, 10, 6),
                CornerRadius = new CornerRadius(8),
                Background = autoSelected ? accentSoftBrush : elevBrush,
                BorderBrush = autoSelected ? accentBorderBrush : borderBrush,
                BorderThickness = new Thickness(autoSelected ? 1.4 : 1.0),
                Content = autoGrid
            };
            autoBtn.Click += (_, _) => GlobalNodeSelected?.Invoke("__AUTO_FASTEST__");
            nodeStack.Children.Add(autoBtn);

            // Find lowest RTT node for ★最优 badge
            string? bestNodeName = null;
            int bestRtt = int.MaxValue;
            foreach (var nd in snap.Nodes)
            {
                if (snap.NodeLatencies.TryGetValue(nd.Name, out int r) && r >= 0 && r < bestRtt)
                {
                    bestRtt = r;
                    bestNodeName = nd.Name;
                }
            }

            foreach (var nd in snap.Nodes)
            {
                bool isSel = string.Equals(selectedGlobal, nd.Name, StringComparison.Ordinal);
                bool isOpt = bestNodeName != null && string.Equals(bestNodeName, nd.Name, StringComparison.Ordinal);
                bool hasRtt = snap.NodeLatencies.TryGetValue(nd.Name, out int rtt);
                string rttLabel = !hasRtt ? "待测速" : (rtt >= 0 ? $"{rtt} ms" : "超时");
                Brush rttFg = !hasRtt ? secBrush : (rtt < 0 ? dangerBrush : (rtt < 160 ? accentTextBrush : warnBrush));

                var nGrid = new Grid { ColumnSpacing = 8 };
                nGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
                nGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
                nGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

                nGrid.Children.Add(new TextBlock
                {
                    Text = $"{(isSel ? "●" : "○")} {nd.Name}",
                    FontSize = 11.5,
                    FontWeight = isSel ? Microsoft.UI.Text.FontWeights.Bold : Microsoft.UI.Text.FontWeights.Medium,
                    Foreground = isSel ? accentTextBrush : priBrush,
                    TextTrimming = TextTrimming.CharacterEllipsis
                });

                var protoBlock = new TextBlock
                {
                    Text = isOpt ? $"{nd.Type.ToUpperInvariant()} ★最优" : nd.Type.ToUpperInvariant(),
                    FontSize = 10,
                    FontWeight = Microsoft.UI.Text.FontWeights.SemiBold,
                    Foreground = isOpt ? accentTextBrush : secBrush,
                    VerticalAlignment = VerticalAlignment.Center
                };
                Grid.SetColumn(protoBlock, 1);
                nGrid.Children.Add(protoBlock);

                var rttBlock = new TextBlock
                {
                    Text = rttLabel,
                    FontSize = 11,
                    FontWeight = Microsoft.UI.Text.FontWeights.Bold,
                    Foreground = rttFg,
                    VerticalAlignment = VerticalAlignment.Center
                };
                Grid.SetColumn(rttBlock, 2);
                nGrid.Children.Add(rttBlock);

                var nBtn = new Button
                {
                    HorizontalAlignment = HorizontalAlignment.Stretch,
                    HorizontalContentAlignment = HorizontalAlignment.Stretch,
                    Padding = new Thickness(10, 6, 10, 6),
                    CornerRadius = new CornerRadius(8),
                    Background = isSel ? accentSoftBrush : elevBrush,
                    BorderBrush = isSel ? accentBorderBrush : borderBrush,
                    BorderThickness = new Thickness(isSel ? 1.4 : 1.0),
                    Content = nGrid
                };
                string chosenNode = nd.Name;
                nBtn.Click += (_, _) => GlobalNodeSelected?.Invoke(chosenNode);
                nodeStack.Children.Add(nBtn);
            }

            var boxInner = new StackPanel { Spacing = 6 };
            boxInner.Children.Add(secHeader);
            boxInner.Children.Add(new ScrollViewer
            {
                Height = 204,
                VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
                Content = nodeStack
            });
            _rootStack.Children.Add(new Border
            {
                Background = wsBrush,
                BorderBrush = borderBrush,
                BorderThickness = new Thickness(1),
                CornerRadius = new CornerRadius(10),
                Padding = new Thickness(8, 6, 8, 8),
                Child = boxInner
            });
        }

        // 4. Quick Toggles & Profile Row + Footer
        var quickRow = new Grid { ColumnSpacing = 6 };
        quickRow.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        quickRow.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });

        var tunBtn = BuildQuickPillButton(
            tunOn ? "● TUN 增强 (开)" : "○ TUN 增强 (关)",
            tunOn, accentSoftBrush, elevBrush, accentBorderBrush, borderBrush, accentTextBrush, secBrush,
            () => ToggleEnhancedTunRequested?.Invoke());
        quickRow.Children.Add(tunBtn);

        var sysBtn = BuildQuickPillButton(
            sysProxyOn ? "● 系统代理 (开)" : "○ 系统代理 (关)",
            sysProxyOn, accentSoftBrush, elevBrush, accentBorderBrush, borderBrush, accentTextBrush, secBrush,
            () => ToggleSystemProxyRequested?.Invoke());
        Grid.SetColumn(sysBtn, 1);
        quickRow.Children.Add(sysBtn);
        _rootStack.Children.Add(quickRow);

        var footerGrid = new Grid { ColumnSpacing = 6 };
        footerGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        footerGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        footerGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

        var openBtn = new Button
        {
            Content = $"打开控制台 · {activeProfileTitle}",
            HorizontalAlignment = HorizontalAlignment.Stretch,
            FontSize = 11.5,
            FontWeight = Microsoft.UI.Text.FontWeights.SemiBold,
            Padding = new Thickness(10, 6, 10, 6),
            CornerRadius = new CornerRadius(8),
            Background = elevBrush,
            Foreground = priBrush,
            BorderBrush = borderBrush,
            BorderThickness = new Thickness(1)
        };
        openBtn.Click += (_, _) =>
        {
            HidePopover();
            OpenMainWindowRequested?.Invoke();
        };
        footerGrid.Children.Add(openBtn);

        var syncBtn = new Button
        {
            Content = "↻ 更新",
            FontSize = 11.5,
            FontWeight = Microsoft.UI.Text.FontWeights.SemiBold,
            Padding = new Thickness(10, 6, 10, 6),
            CornerRadius = new CornerRadius(8),
            Background = elevBrush,
            Foreground = accentTextBrush,
            BorderBrush = borderBrush,
            BorderThickness = new Thickness(1)
        };
        syncBtn.Click += (_, _) => RefreshSubscriptionRequested?.Invoke();
        Grid.SetColumn(syncBtn, 1);
        footerGrid.Children.Add(syncBtn);

        var quitBtn = new Button
        {
            Content = "退出",
            FontSize = 11.5,
            FontWeight = Microsoft.UI.Text.FontWeights.SemiBold,
            Padding = new Thickness(10, 6, 10, 6),
            CornerRadius = new CornerRadius(8),
            Background = new SolidColorBrush(Color.FromArgb(30, 239, 68, 68)),
            Foreground = dangerBrush,
            BorderBrush = new SolidColorBrush(Color.FromArgb(80, 239, 68, 68)),
            BorderThickness = new Thickness(1)
        };
        quitBtn.Click += (_, _) =>
        {
            HidePopover();
            ExitAppRequested?.Invoke();
        };
        Grid.SetColumn(quitBtn, 2);
        footerGrid.Children.Add(quitBtn);

        _rootStack.Children.Add(footerGrid);
    }

    private static Grid BuildSectionHeader(
        string leftText, string rightText, Brush leftFg, Brush rightFg, Action onRightClick)
    {
        var g = new Grid { Padding = new Thickness(4, 0, 2, 0) };
        g.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        g.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        g.Children.Add(new TextBlock
        {
            Text = leftText,
            FontSize = 11,
            FontWeight = Microsoft.UI.Text.FontWeights.SemiBold,
            Foreground = leftFg,
            VerticalAlignment = VerticalAlignment.Center,
            TextTrimming = TextTrimming.CharacterEllipsis
        });
        var btn = new Button
        {
            Content = rightText,
            FontSize = 11,
            FontWeight = Microsoft.UI.Text.FontWeights.Bold,
            Padding = new Thickness(7, 2, 7, 2),
            CornerRadius = new CornerRadius(6),
            Background = new SolidColorBrush(Colors.Transparent),
            Foreground = rightFg,
            BorderThickness = new Thickness(0)
        };
        btn.Click += (_, _) => onRightClick();
        Grid.SetColumn(btn, 1);
        g.Children.Add(btn);
        return g;
    }

    private static Button BuildQuickPillButton(
        string label, bool active, Brush activeBg, Brush idleBg, Brush activeBorder, Brush idleBorder,
        Brush activeFg, Brush idleFg, Action onClick)
    {
        var btn = new Button
        {
            Content = label,
            HorizontalAlignment = HorizontalAlignment.Stretch,
            FontSize = 11.5,
            FontWeight = active ? Microsoft.UI.Text.FontWeights.Bold : Microsoft.UI.Text.FontWeights.SemiBold,
            Padding = new Thickness(8, 6, 8, 6),
            CornerRadius = new CornerRadius(8),
            Background = active ? activeBg : idleBg,
            BorderBrush = active ? activeBorder : idleBorder,
            BorderThickness = new Thickness(1),
            Foreground = active ? activeFg : idleFg
        };
        btn.Click += (_, _) => onClick();
        return btn;
    }

    private static int ResolveActiveLatencyMs(EngineStatusSnapshot snap, OutboundRoutingMode mode)
    {
        if (mode == OutboundRoutingMode.Direct) return -1;
        string target = mode == OutboundRoutingMode.Global
            ? snap.EffectiveGlobalNode
            : (snap.Groups.Count > 0 ? snap.Groups[0].Selected : snap.EffectiveGlobalNode);
        for (int depth = 0; depth < 8; depth++)
        {
            var grp = snap.Groups.FirstOrDefault(g => string.Equals(g.Name, target, StringComparison.Ordinal));
            if (grp == null) break;
            target = !string.IsNullOrEmpty(grp.Selected) ? grp.Selected : (grp.Members.FirstOrDefault() ?? "DIRECT");
        }
        return snap.NodeLatencies.TryGetValue(target, out int ms) && ms >= 0 ? ms : -1;
    }
}
