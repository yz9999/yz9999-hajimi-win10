using System.Globalization;
using System.Net.Http;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Media;
using Windows.UI;

namespace HajimiWinApp.Themes;

public sealed class HajimiThemeTokenSet
{
    [JsonPropertyName("id")] public string Id { get; set; } = "theme-01-emerald-original";
    [JsonPropertyName("code")] public string Code { get; set; } = "#01";
    [JsonPropertyName("name")] public string Name { get; set; } = "翡翠原石 · 现版精修";
    [JsonPropertyName("englishName")] public string EnglishName { get; set; } = "Hajimi Emerald Original";
    [JsonPropertyName("category")] public string Category { get; set; } = "macOS 原生进化";
    [JsonPropertyName("layoutStyle")] public string LayoutStyle { get; set; } = "L1 经典左栏+Bento";
    [JsonPropertyName("appearanceMode")] public string AppearanceMode { get; set; } = "system";
    [JsonPropertyName("cardCornerRadius")] public double CardCornerRadius { get; set; } = 14.0;
    [JsonPropertyName("innerCornerRadius")] public double InnerCornerRadius { get; set; } = 10.0;
    [JsonPropertyName("workspaceHex")] public string WorkspaceHex { get; set; } = "#0F1214";
    [JsonPropertyName("sidebarHex")] public string SidebarHex { get; set; } = "#14181B";
    [JsonPropertyName("panelHex")] public string PanelHex { get; set; } = "#1A1F22";
    [JsonPropertyName("elevatedPanelHex")] public string ElevatedPanelHex { get; set; } = "#202629";
    [JsonPropertyName("mutedPanelHex")] public string MutedPanelHex { get; set; } = "#14181B";
    [JsonPropertyName("accentHex")] public string AccentHex { get; set; } = "#2ED19C";
    [JsonPropertyName("accentTextHex")] public string AccentTextHex { get; set; } = "#34E8B8";
    [JsonPropertyName("uploadAccentHex")] public string UploadAccentHex { get; set; } = "#59B0FA";
    [JsonPropertyName("indigoAccentHex")] public string IndigoAccentHex { get; set; } = "#8A94FA";
    [JsonPropertyName("textPrimaryHex")] public string TextPrimaryHex { get; set; } = "#ECFDF5";
    [JsonPropertyName("textSecondaryHex")] public string TextSecondaryHex { get; set; } = "#8DA399";
    [JsonPropertyName("borderAlpha")] public double BorderAlpha { get; set; } = 0.13;
    [JsonPropertyName("highlightAlpha")] public double HighlightAlpha { get; set; } = 0.08;
    [JsonPropertyName("featureSummary")] public string FeatureSummary { get; set; } = "";
    [JsonPropertyName("description")] public string Description { get; set; } = "";

    // Bindable live swatch brushes for the 50-theme visual gallery cards
    [JsonIgnore] public SolidColorBrush SwatchWorkspace => new(HajimiWinThemeEngine.ParseHexColor(WorkspaceHex, Color.FromArgb(255, 15, 18, 20)));
    [JsonIgnore] public SolidColorBrush SwatchSidebar => new(HajimiWinThemeEngine.ParseHexColor(SidebarHex, Color.FromArgb(255, 20, 24, 27)));
    [JsonIgnore] public SolidColorBrush SwatchPanel => new(HajimiWinThemeEngine.ParseHexColor(PanelHex, Color.FromArgb(255, 26, 31, 34)));
    [JsonIgnore] public SolidColorBrush SwatchAccent => new(HajimiWinThemeEngine.ParseHexColor(AccentHex, Color.FromArgb(255, 46, 209, 156)));
    [JsonIgnore] public SolidColorBrush SwatchUpload => new(HajimiWinThemeEngine.ParseHexColor(UploadAccentHex, Color.FromArgb(255, 89, 176, 250)));
}

public sealed class HajimiThemePackDocument
{
    [JsonPropertyName("schemaVersion")] public string SchemaVersion { get; set; } = "1.0";
    [JsonPropertyName("packName")] public string PackName { get; set; } = "";
    [JsonPropertyName("themes")] public List<HajimiThemeTokenSet> Themes { get; set; } = [];
}

/// Loads all 50 built-in `.hajimitheme.json` themes (and imported local/HTTPS packs)
/// and hot-swaps BOTH Hajimi semantic brushes AND WinUI 3 lightweight control resources.
public sealed class HajimiWinThemeEngine
{
    private const int MaxThemeJsonBytes = 1024 * 1024; // 1 MiB safety bound
    private readonly List<HajimiThemeTokenSet> _themes = [];
    private static readonly HttpClient SharedHttp = new() { Timeout = TimeSpan.FromSeconds(10) };

    public IReadOnlyList<HajimiThemeTokenSet> Themes => _themes;
    public HajimiThemeTokenSet ActiveTheme { get; private set; } = new();

    public event Action<HajimiThemeTokenSet>? ThemeChanged;

    public int LoadBuiltInPack(string? customPackPath = null)
    {
        string path = customPackPath ?? Path.Combine(
            AppContext.BaseDirectory, "Themes", "hajimi-all-50-themes-pack.hajimitheme.json");
        if (!File.Exists(path))
            return 0;

        string json = File.ReadAllText(path);
        return ImportJsonString(json, replaceExisting: true);
    }

    public int ImportFromFile(string filePath)
    {
        var info = new FileInfo(filePath);
        if (!info.Exists || info.Length <= 0 || info.Length > MaxThemeJsonBytes)
            throw new InvalidOperationException("主题文件不存在或超过 1 MiB 安全大小限制");
        return ImportJsonString(File.ReadAllText(filePath), replaceExisting: false);
    }

    public async Task<int> ImportFromHttpsUrlAsync(string httpsUrl, CancellationToken ct = default)
    {
        if (!Uri.TryCreate(httpsUrl, UriKind.Absolute, out Uri? uri) || uri.Scheme != Uri.UriSchemeHttps)
            throw new ArgumentException("仅允许通过 HTTPS 安全链接导入远程主题包");

        using HttpResponseMessage resp = await SharedHttp.GetAsync(uri, HttpCompletionOption.ResponseHeadersRead, ct);
        resp.EnsureSuccessStatusCode();
        byte[] bytes = await resp.Content.ReadAsByteArrayAsync(ct);
        if (bytes.Length == 0 || bytes.Length > MaxThemeJsonBytes)
            throw new InvalidOperationException("远程主题响应为空或超过 1 MiB 上限");

        return ImportJsonString(System.Text.Encoding.UTF8.GetString(bytes), replaceExisting: false);
    }

    public int ImportJsonString(string json, bool replaceExisting)
    {
        if (string.IsNullOrWhiteSpace(json) || json.Length > MaxThemeJsonBytes)
            return 0;

        List<HajimiThemeTokenSet> parsedList = [];
        if (json.Contains("\"themes\"", StringComparison.Ordinal))
        {
            var pack = JsonSerializer.Deserialize<HajimiThemePackDocument>(json);
            if (pack?.Themes != null)
                parsedList.AddRange(pack.Themes);
        }
        else
        {
            var single = JsonSerializer.Deserialize<HajimiThemeTokenSet>(json);
            if (single != null && !string.IsNullOrWhiteSpace(single.Id))
                parsedList.Add(single);
        }

        if (parsedList.Count == 0)
            return 0;

        if (replaceExisting)
            _themes.Clear();

        int count = 0;
        foreach (var t in parsedList)
        {
            if (string.IsNullOrWhiteSpace(t.Id)) continue;
            int existingIdx = _themes.FindIndex(x => x.Id == t.Id);
            if (existingIdx >= 0) _themes[existingIdx] = t;
            else _themes.Add(t);
            count++;
        }

        if (_themes.Count > 0 && string.IsNullOrEmpty(ActiveTheme.Id))
            ActiveTheme = _themes[0];

        return count;
    }

    public bool ApplyTheme(string themeId, FrameworkElement? rootElement, ResourceDictionary targetResources)
    {
        var exact = _themes.FirstOrDefault(t => t.Id == themeId);
        var found = exact ?? _themes.FirstOrDefault() ?? new HajimiThemeTokenSet();
        ActiveTheme = found;

        Color workspace = ParseHexColor(found.WorkspaceHex, Color.FromArgb(255, 15, 18, 20));
        Color sidebar = ParseHexColor(found.SidebarHex, Color.FromArgb(255, 20, 24, 27));
        Color panel = ParseHexColor(found.PanelHex, Color.FromArgb(255, 26, 31, 34));
        Color elevated = ParseHexColor(found.ElevatedPanelHex, Color.FromArgb(255, 32, 38, 41));
        Color muted = ParseHexColor(found.MutedPanelHex, sidebar);
        Color accent = ParseHexColor(found.AccentHex, Color.FromArgb(255, 46, 209, 156));
        Color accentText = ParseHexColor(found.AccentTextHex, accent);
        Color upload = ParseHexColor(found.UploadAccentHex, Color.FromArgb(255, 89, 176, 250));
        Color indigo = ParseHexColor(found.IndigoAccentHex, Color.FromArgb(255, 138, 148, 250));
        Color textPrimary = ParseHexColor(found.TextPrimaryHex, Color.FromArgb(255, 236, 253, 245));
        Color textSecondary = ParseHexColor(found.TextSecondaryHex, Color.FromArgb(255, 141, 163, 153));

        bool isLightSurface = (0.299 * workspace.R + 0.587 * workspace.G + 0.114 * workspace.B) > 150.0;
        byte borderA = (byte)Math.Clamp((int)Math.Round(found.BorderAlpha * 255.0), 18, 160);
        Color borderColor = Color.FromArgb(borderA, textPrimary.R, textPrimary.G, textPrimary.B);
        Color accentSoft = Color.FromArgb(isLightSurface ? (byte)32 : (byte)38, accent.R, accent.G, accent.B);
        Color accentBorder = Color.FromArgb(isLightSurface ? (byte)150 : (byte)135, accent.R, accent.G, accent.B);
        Color onAccentText = (0.299 * accent.R + 0.587 * accent.G + 0.114 * accent.B) > 155.0
            ? Color.FromArgb(255, 10, 18, 15)
            : Color.FromArgb(255, 250, 253, 252);
        Color hoverElevated = BlendColor(elevated, textPrimary, 0.08);
        Color pressedElevated = BlendColor(elevated, workspace, 0.25);

        SetBrush(targetResources, "HajimiWorkspaceBrush", workspace);
        SetBrush(targetResources, "HajimiSidebarBrush", sidebar);
        SetBrush(targetResources, "HajimiPanelBrush", panel);
        SetBrush(targetResources, "HajimiElevatedPanelBrush", elevated);
        SetBrush(targetResources, "HajimiHoverPanelBrush", hoverElevated);
        SetBrush(targetResources, "HajimiMutedPanelBrush", muted);
        SetBrush(targetResources, "HajimiAccentBrush", accent);
        SetBrush(targetResources, "HajimiAccentSoftBrush", accentSoft);
        SetBrush(targetResources, "HajimiAccentBorderBrush", accentBorder);
        SetBrush(targetResources, "HajimiOnAccentTextBrush", onAccentText);
        SetBrush(targetResources, "HajimiAccentTextBrush", accentText);
        SetBrush(targetResources, "HajimiUploadAccentBrush", upload);
        SetBrush(targetResources, "HajimiIndigoAccentBrush", indigo);
        SetBrush(targetResources, "HajimiTextPrimaryBrush", textPrimary);
        SetBrush(targetResources, "HajimiTextSecondaryBrush", textSecondary);
        SetBrush(targetResources, "HajimiBorderBrush", borderColor);

        // Override WinUI 3 Lightweight Styling keys so native Buttons, TextBoxes, ComboBoxes,
        // and ToggleSwitches match the active macOS-unified Hajimi theme seamlessly!
        SetBrush(targetResources, "ButtonBackground", elevated);
        SetBrush(targetResources, "ButtonBackgroundPointerOver", hoverElevated);
        SetBrush(targetResources, "ButtonBackgroundPressed", pressedElevated);
        SetBrush(targetResources, "ButtonForeground", textPrimary);
        SetBrush(targetResources, "ButtonForegroundPointerOver", textPrimary);
        SetBrush(targetResources, "ButtonForegroundPressed", textSecondary);
        SetBrush(targetResources, "ButtonBorderBrush", borderColor);
        SetBrush(targetResources, "ButtonBorderBrushPointerOver", accentBorder);

        SetBrush(targetResources, "TextControlBackground", muted);
        SetBrush(targetResources, "TextControlBackgroundPointerOver", elevated);
        SetBrush(targetResources, "TextControlBackgroundFocused", muted);
        SetBrush(targetResources, "TextControlForeground", textPrimary);
        SetBrush(targetResources, "TextControlForegroundPointerOver", textPrimary);
        SetBrush(targetResources, "TextControlForegroundFocused", textPrimary);
        SetBrush(targetResources, "TextControlPlaceholderForeground", textSecondary);
        SetBrush(targetResources, "TextControlBorderBrush", borderColor);
        SetBrush(targetResources, "TextControlBorderBrushPointerOver", accentBorder);
        SetBrush(targetResources, "TextControlBorderBrushFocused", accent);

        SetBrush(targetResources, "ToggleSwitchFillOn", accent);
        SetBrush(targetResources, "ToggleSwitchFillOnPointerOver", BlendColor(accent, Color.FromArgb(255, 255, 255, 255), 0.12));
        SetBrush(targetResources, "ToggleSwitchFillOnPressed", accent);
        SetBrush(targetResources, "ToggleSwitchKnobFillOn", onAccentText);

        double outerR = Math.Clamp(found.CardCornerRadius, 4.0, 28.0);
        double innerR = Math.Clamp(found.InnerCornerRadius, 4.0, 20.0);
        targetResources["HajimiCardCornerRadius"] = new CornerRadius(outerR);
        targetResources["HajimiInnerCornerRadius"] = new CornerRadius(innerR);

        if (rootElement != null)
        {
            rootElement.RequestedTheme = isLightSurface ? ElementTheme.Light : ElementTheme.Dark;
        }

        ThemeChanged?.Invoke(found);
        return exact != null;
    }

    private static Color BlendColor(Color a, Color b, double t)
    {
        double inv = 1.0 - t;
        return Color.FromArgb(
            255,
            (byte)Math.Clamp((int)(a.R * inv + b.R * t), 0, 255),
            (byte)Math.Clamp((int)(a.G * inv + b.G * t), 0, 255),
            (byte)Math.Clamp((int)(a.B * inv + b.B * t), 0, 255));
    }

    public static Color ParseHexColor(string? hex, Color fallback)
    {
        if (string.IsNullOrWhiteSpace(hex)) return fallback;
        ReadOnlySpan<char> span = hex.AsSpan().Trim();
        if (span.StartsWith("#")) span = span[1..];
        if (span.Length == 6 &&
            uint.TryParse(span, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out uint rgb))
        {
            return Color.FromArgb(
                255,
                (byte)((rgb >> 16) & 0xFF),
                (byte)((rgb >> 8) & 0xFF),
                (byte)(rgb & 0xFF));
        }
        if (span.Length == 8 &&
            uint.TryParse(span, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out uint argb))
        {
            return Color.FromArgb(
                (byte)((argb >> 24) & 0xFF),
                (byte)((argb >> 16) & 0xFF),
                (byte)((argb >> 8) & 0xFF),
                (byte)(argb & 0xFF));
        }
        return fallback;
    }

    private static void SetBrush(ResourceDictionary dict, string key, Color color)
    {
        if (dict.TryGetValue(key, out object? existing) && existing is SolidColorBrush brush)
        {
            brush.Color = color;
        }
        else
        {
            dict[key] = new SolidColorBrush(color);
        }
    }
}
