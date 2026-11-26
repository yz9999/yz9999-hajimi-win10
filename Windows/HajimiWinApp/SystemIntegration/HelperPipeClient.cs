using System.Diagnostics;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using HajimiWinApp.Interop;

namespace HajimiWinApp.SystemIntegration;

public sealed class HelperPipeResponseDto
{
    [JsonPropertyName("ok")] public bool Ok { get; set; }
    [JsonPropertyName("message")] public string? Message { get; set; }
    [JsonPropertyName("errorCode")] public string? ErrorCode { get; set; }
    [JsonPropertyName("shmSectionHandle")] public ulong ShmSectionHandle { get; set; }
    [JsonPropertyName("shmRxEventHandle")] public ulong ShmRxEventHandle { get; set; }
    [JsonPropertyName("shmTxEventHandle")] public ulong ShmTxEventHandle { get; set; }
    [JsonPropertyName("state")] public HelperStateDto? State { get; set; }
}

public sealed class HelperStateDto
{
    [JsonPropertyName("running")] public bool Running { get; set; }
    [JsonPropertyName("phase")] public string? Phase { get; set; }
    [JsonPropertyName("sessionToken")] public string? SessionToken { get; set; }
    [JsonPropertyName("tunnelInterface")] public string? TunnelInterface { get; set; }
    [JsonPropertyName("physicalInterface")] public string? PhysicalInterface { get; set; }
}

/// Client for `\\.\pipe\HajimiHelperPipe` speaking Protocol v8:
/// Automatically bootstraps co-located `HajimiHelperService.exe --install` via standard Windows UAC
/// if the service is not yet installed (e.g. Portable ZIP mode) or currently stopped.
public sealed partial class HelperPipeClient : IDisposable
{
    private const string PipeName = "HajimiHelperPipe";
    private const uint FileMapAllAccess = 0x000F001Fu;
    private const nuint ShmTotalBytes = 4096u + 2u * 8u * 1024u * 1024u;

    [LibraryImport("kernel32.dll", SetLastError = true)]
    private static partial IntPtr MapViewOfFile(
        IntPtr hFileMappingObject, uint dwDesiredAccess, uint dwFileOffsetHigh, uint dwFileOffsetLow, nuint dwNumberOfBytesToMap);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool UnmapViewOfFile(IntPtr lpBaseAddress);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool CloseHandle(IntPtr hObject);

    private IntPtr _shmSectionHandle;
    private IntPtr _shmMappedView;
    private IntPtr _rxEventHandle;
    private IntPtr _txEventHandle;
    private string? _sessionToken;
    private CancellationTokenSource? _heartbeatCts;
    private Task? _heartbeatTask;

    public bool IsEnhancedModeActive => !string.IsNullOrEmpty(_sessionToken);
    public string ActiveTunnelInterface { get; private set; } = "";

    public async Task EnableEnhancedModeAsync(
        HajimiEngineClient engine,
        IReadOnlyList<string> bypassAddresses,
        IReadOnlyList<string> excludedRoutes,
        CancellationToken ct = default)
    {
        await DisableEnhancedModeAsync(engine);

        HelperPipeResponseDto? prepResp = null;
        Exception? initialConnectEx = null;
        try
        {
            prepResp = await SendRequestAsync(new { action = "prepare", fakeIPEnabled = true }, ct, timeoutMs: 1200);
        }
        catch (Exception ex)
        {
            initialConnectEx = ex;
        }

        bool needsRebootstrap = prepResp == null ||
            (!prepResp.Ok && (
                string.Equals(prepResp.ErrorCode, "unauthorized", StringComparison.OrdinalIgnoreCase) ||
                (prepResp.Message?.Contains("WinVerifyTrust", StringComparison.OrdinalIgnoreCase) ?? false)));
        if (needsRebootstrap)
        {
            if (!await TryBootstrapColocatedServiceWithUacAsync(ct))
            {
                if (initialConnectEx != null) throw initialConnectEx;
            }
            else
            {
                prepResp = await SendRequestAsync(new { action = "prepare", fakeIPEnabled = true }, ct, timeoutMs: 3000);
            }
        }

        if (!prepResp.Ok || prepResp.State?.SessionToken == null || prepResp.ShmSectionHandle == 0)
        {
            throw new InvalidOperationException(
                $"特权服务 prepare 失败：{prepResp.Message ?? prepResp.ErrorCode ?? "未知错误"}");
        }

        _shmSectionHandle = (IntPtr)prepResp.ShmSectionHandle;
        _rxEventHandle = (IntPtr)prepResp.ShmRxEventHandle;
        _txEventHandle = (IntPtr)prepResp.ShmTxEventHandle;
        _sessionToken = prepResp.State.SessionToken;
        ActiveTunnelInterface = prepResp.State.TunnelInterface ?? "Hajimi Tunnel";

        _shmMappedView = MapViewOfFile(_shmSectionHandle, FileMapAllAccess, 0, 0, ShmTotalBytes);
        if (_shmMappedView == IntPtr.Zero)
        {
            await DisableEnhancedModeAsync(engine);
            throw new InvalidOperationException("映射 16 MiB 共享内存隧道环形缓冲区失败");
        }

        if (!engine.AttachSharedMemoryTunnel(_shmMappedView, (nuint)_rxEventHandle, (nuint)_txEventHandle))
        {
            await DisableEnhancedModeAsync(engine);
            throw new InvalidOperationException("HajimiEngine 挂载共享内存隧道数据面失败");
        }

        var commitResp = await SendRequestAsync(new
        {
            action = "commit",
            sessionToken = _sessionToken,
            fakeIPEnabled = true,
            bypassAddresses,
            excludedRoutes
        }, ct);

        if (!commitResp.Ok)
        {
            await DisableEnhancedModeAsync(engine);
            throw new InvalidOperationException(
                $"特权服务 commit 路由与 WFP 防泄漏失败：{commitResp.Message ?? commitResp.ErrorCode}");
        }

        _heartbeatCts = new CancellationTokenSource();
        string boundToken = _sessionToken;
        _heartbeatTask = Task.Run(async () =>
        {
            using var timer = new PeriodicTimer(TimeSpan.FromSeconds(1));
            while (await timer.WaitForNextTickAsync(_heartbeatCts.Token))
            {
                try
                {
                    await SendRequestAsync(new { action = "status", sessionToken = boundToken }, _heartbeatCts.Token);
                }
                catch
                {
                    // Transient IPC hiccup; retry on next 1s tick within 3s watchdog budget
                }
            }
        }, _heartbeatCts.Token);
    }

    private static async Task<bool> TryBootstrapColocatedServiceWithUacAsync(CancellationToken ct)
    {
        string helperExe = Path.Combine(AppContext.BaseDirectory, "HajimiHelperService.exe");
        if (!File.Exists(helperExe)) return false;

        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = helperExe,
                Arguments = "--install",
                Verb = "runas",
                UseShellExecute = true,
                WindowStyle = ProcessWindowStyle.Hidden
            };
            using var proc = Process.Start(psi);
            if (proc == null) return false;
            await proc.WaitForExitAsync(ct);
            if (proc.ExitCode != 0) return false;

            await Task.Delay(400, ct);
            return true;
        }
        catch
        {
            return false;
        }
    }

    public async Task DisableEnhancedModeAsync(HajimiEngineClient engine)
    {
        if (_heartbeatCts != null)
        {
            await _heartbeatCts.CancelAsync();
            if (_heartbeatTask != null)
            {
                try { await _heartbeatTask; } catch { }
            }
            _heartbeatCts.Dispose();
            _heartbeatCts = null;
            _heartbeatTask = null;
        }

        engine.DetachSharedMemoryTunnel();

        if (!string.IsNullOrEmpty(_sessionToken))
        {
            string tok = _sessionToken;
            _sessionToken = null;
            try
            {
                await SendRequestAsync(new { action = "stop", sessionToken = tok }, CancellationToken.None);
            }
            catch { }
        }

        ReleaseNativeHandles();
        ActiveTunnelInterface = "";
    }

    private static async Task<HelperPipeResponseDto> SendRequestAsync(
        object payload, CancellationToken ct, int timeoutMs = 2000)
    {
        using var pipe = new NamedPipeClientStream(".", PipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
        await pipe.ConnectAsync(timeoutMs, ct);

        string reqLine = JsonSerializer.Serialize(payload) + "\n";
        byte[] reqBytes = Encoding.UTF8.GetBytes(reqLine);
        await pipe.WriteAsync(reqBytes, ct);
        await pipe.FlushAsync(ct);

        using var reader = new StreamReader(pipe, Encoding.UTF8, detectEncodingFromByteOrderMarks: false, bufferSize: 8192, leaveOpen: true);
        string? respLine = await reader.ReadLineAsync(ct);
        if (string.IsNullOrWhiteSpace(respLine))
            return new HelperPipeResponseDto { Ok = false, Message = "Empty response from HajimiHelperService" };

        return JsonSerializer.Deserialize<HelperPipeResponseDto>(respLine)
               ?? new HelperPipeResponseDto { Ok = false, Message = "Invalid JSON from HajimiHelperService" };
    }

    private void ReleaseNativeHandles()
    {
        if (_shmMappedView != IntPtr.Zero)
        {
            UnmapViewOfFile(_shmMappedView);
            _shmMappedView = IntPtr.Zero;
        }
        if (_shmSectionHandle != IntPtr.Zero)
        {
            CloseHandle(_shmSectionHandle);
            _shmSectionHandle = IntPtr.Zero;
        }
        if (_rxEventHandle != IntPtr.Zero)
        {
            CloseHandle(_rxEventHandle);
            _rxEventHandle = IntPtr.Zero;
        }
        if (_txEventHandle != IntPtr.Zero)
        {
            CloseHandle(_txEventHandle);
            _txEventHandle = IntPtr.Zero;
        }
    }

    public void Dispose()
    {
        _heartbeatCts?.Cancel();
        ReleaseNativeHandles();
    }
}
