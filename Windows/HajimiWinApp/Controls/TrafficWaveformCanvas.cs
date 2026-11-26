using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Shapes;
using Windows.Foundation;
using Windows.UI;

namespace HajimiWinApp.Controls;

/// DirectComposition GPU-accelerated dual-series (Download / Upload) 60-second ring buffer
/// waveform control using native WinUI 3 vector shapes.
public sealed partial class TrafficWaveformCanvas : UserControl
{
    private const int HistorySamples = 60;
    private readonly ulong[] _downloadRing = new ulong[HistorySamples];
    private readonly ulong[] _uploadRing = new ulong[HistorySamples];
    private int _writeIndex;

    private readonly Canvas _surface;
    private readonly Line[] _gridLines = new Line[3];
    private readonly Line _p95Line;
    private readonly Polygon _downFill;
    private readonly Polyline _downStroke;
    private readonly Polygon _upFill;
    private readonly Polyline _upStroke;
    private readonly TextBlock _scaleLabel;

    private Color _downloadColor = Color.FromArgb(255, 46, 209, 156);
    private Color _uploadColor = Color.FromArgb(255, 89, 176, 250);

    public TrafficWaveformCanvas()
    {
        _surface = new Canvas();

        var gridBrush = new SolidColorBrush(Color.FromArgb(32, 255, 255, 255));
        for (int i = 0; i < _gridLines.Length; i++)
        {
            _gridLines[i] = new Line { Stroke = gridBrush, StrokeThickness = 1.0 };
            _surface.Children.Add(_gridLines[i]);
        }

        _p95Line = new Line { StrokeThickness = 1.0 };
        _p95Line.StrokeDashArray.Add(4.0);
        _p95Line.StrokeDashArray.Add(3.0);
        _surface.Children.Add(_p95Line);

        _downFill = new Polygon();
        _downStroke = new Polyline { StrokeThickness = 2.0, StrokeLineJoin = PenLineJoin.Round };
        _upFill = new Polygon();
        _upStroke = new Polyline { StrokeThickness = 2.0, StrokeLineJoin = PenLineJoin.Round };

        _surface.Children.Add(_downFill);
        _surface.Children.Add(_upFill);
        _surface.Children.Add(_downStroke);
        _surface.Children.Add(_upStroke);

        _scaleLabel = new TextBlock
        {
            FontSize = 11.5,
            Text = "峰值 64 KB/s  ·  P95 0 B/s"
        };
        Canvas.SetLeft(_scaleLabel, 6.0);
        Canvas.SetTop(_scaleLabel, 2.0);
        _surface.Children.Add(_scaleLabel);

        ApplyBrushes(Color.FromArgb(180, 141, 163, 153));
        SizeChanged += (_, sz) =>
        {
            _surface.Clip = new RectangleGeometry
            {
                Rect = new Rect(0, 0, Math.Max(0, sz.NewSize.Width), Math.Max(0, sz.NewSize.Height))
            };
            Redraw();
        };
        Content = _surface;
    }

    public void UpdatePalette(Color downloadAccent, Color uploadAccent, Color textSecondary)
    {
        _downloadColor = downloadAccent;
        _uploadColor = uploadAccent;
        ApplyBrushes(textSecondary);
        Redraw();
    }

    public void PushSample(ulong downloadBytesPerSec, ulong uploadBytesPerSec)
    {
        _downloadRing[_writeIndex] = downloadBytesPerSec;
        _uploadRing[_writeIndex] = uploadBytesPerSec;
        _writeIndex = (_writeIndex + 1) % HistorySamples;
        Redraw();
    }

    private void ApplyBrushes(Color labelColor)
    {
        _downStroke.Stroke = new SolidColorBrush(_downloadColor);
        _upStroke.Stroke = new SolidColorBrush(_uploadColor);
        _p95Line.Stroke = new SolidColorBrush(Color.FromArgb(100, _downloadColor.R, _downloadColor.G, _downloadColor.B));
        _scaleLabel.Foreground = new SolidColorBrush(labelColor);

        _downFill.Fill = CreateVerticalGradient(_downloadColor);
        _upFill.Fill = CreateVerticalGradient(_uploadColor);
    }

    private static LinearGradientBrush CreateVerticalGradient(Color c)
    {
        var brush = new LinearGradientBrush
        {
            StartPoint = new Point(0, 0),
            EndPoint = new Point(0, 1)
        };
        brush.GradientStops.Add(new GradientStop { Color = Color.FromArgb(72, c.R, c.G, c.B), Offset = 0.0 });
        brush.GradientStops.Add(new GradientStop { Color = Color.FromArgb(4, c.R, c.G, c.B), Offset = 1.0 });
        return brush;
    }

    private void Redraw()
    {
        double width = ActualWidth;
        double height = ActualHeight;
        if (width < 32.0 || height < 24.0) return;

        const double padTop = 20.0;
        const double padBottom = 8.0;
        double plotH = Math.Max(10.0, height - padTop - padBottom);

        for (int g = 0; g < _gridLines.Length; g++)
        {
            double gy = padTop + plotH * ((g + 1) / 4.0);
            _gridLines[g].X1 = 0;
            _gridLines[g].X2 = width;
            _gridLines[g].Y1 = gy;
            _gridLines[g].Y2 = gy;
        }

        ulong maxVal = 64 * 1024;
        Span<ulong> combined = stackalloc ulong[HistorySamples];
        for (int i = 0; i < HistorySamples; i++)
        {
            int idx = (_writeIndex + i) % HistorySamples;
            ulong d = _downloadRing[idx];
            ulong u = _uploadRing[idx];
            if (d > maxVal) maxVal = d;
            if (u > maxVal) maxVal = u;
            combined[i] = Math.Max(d, u);
        }
        combined.Sort();
        ulong p95Val = combined[(int)(HistorySamples * 0.95)];

        double p95Y = padTop + plotH * (1.0 - (double)p95Val / maxVal);
        _p95Line.X1 = 0;
        _p95Line.X2 = width;
        _p95Line.Y1 = p95Y;
        _p95Line.Y2 = p95Y;

        RebuildGeometry(_downloadRing, maxVal, width, padTop, plotH, _downStroke, _downFill);
        RebuildGeometry(_uploadRing, maxVal, width, padTop, plotH, _upStroke, _upFill);

        _scaleLabel.Text = $"峰值 {FormatRate(maxVal)}  ·  P95 {FormatRate(p95Val)}";
    }

    private void RebuildGeometry(
        ulong[] ring,
        ulong maxVal,
        double width,
        double padTop,
        double plotH,
        Polyline strokeLine,
        Polygon areaPoly)
    {
        double stepX = width / (HistorySamples - 1);
        var strokePts = new PointCollection();
        var fillPts = new PointCollection { new Point(0, padTop + plotH) };

        for (int i = 0; i < HistorySamples; i++)
        {
            int idx = (_writeIndex + i) % HistorySamples;
            double x = i * stepX;
            double norm = Math.Clamp((double)ring[idx] / maxVal, 0.0, 1.0);
            double y = padTop + plotH * (1.0 - norm);
            var pt = new Point(x, y);
            strokePts.Add(pt);
            fillPts.Add(pt);
        }
        fillPts.Add(new Point(width, padTop + plotH));

        strokeLine.Points = strokePts;
        areaPoly.Points = fillPts;
    }

    public static string FormatRate(ulong bytesPerSec)
    {
        if (bytesPerSec >= 1024UL * 1024 * 1024)
            return $"{bytesPerSec / (1024.0 * 1024 * 1024):F2} GB/s";
        if (bytesPerSec >= 1024UL * 1024)
            return $"{bytesPerSec / (1024.0 * 1024):F1} MB/s";
        if (bytesPerSec >= 1024UL)
            return $"{bytesPerSec / 1024.0:F0} KB/s";
        return $"{bytesPerSec} B/s";
    }
}
