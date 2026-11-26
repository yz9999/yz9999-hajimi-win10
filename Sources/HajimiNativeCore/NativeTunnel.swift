import Foundation
import Darwin
import HajimiCore
import HajimiEngineCBridge

public struct NativeTunnelStatistics: Equatable {
    public let activeFlows: Int
    public let totalFlows: Int
    public let uploadedBytes: UInt64
    public let downloadedBytes: UInt64

    public init(activeFlows: Int, totalFlows: Int, uploadedBytes: UInt64, downloadedBytes: UInt64) {
        self.activeFlows = activeFlows
        self.totalFlows = totalFlows
        self.uploadedBytes = uploadedBytes
        self.downloadedBytes = downloadedBytes
    }
}

public enum NativeTunnelError: LocalizedError {
    case invalidDescriptor
    case attachFailed
    case unsupportedDirectCreation

    public var errorDescription: String? {
        switch self {
        case .invalidDescriptor: return "无效的 utun 虚拟网卡文件描述符"
        case .attachFailed: return "C++ 统一内核接管 utun 数据面失败"
        case .unsupportedDirectCreation: return "请通过特权 Helper 创建并传递 utun 文件描述符"
        }
    }
}

/// Thin Swift Bridge over `UserspacePacketTunnel::attachUtunFd` (`HajimiEngineCAPI`).
/// Eliminates the duplicate 5,091-line Swift userspace TCP/UDP/ICMP stack while keeping
/// 100% compatibility with `EnhancedModeManager` on macOS.
public final class NativeTunnel {
    public static var physicalInterfaceName: String? {
        didSet {
            NativePacketRouter.setOutboundInterface(name: physicalInterfaceName)
        }
    }

    public private(set) var interfaceName: String?
    private let router: NativePacketRouter
    private let lock = NSLock()
    private var ownedFd: Int32 = -1

    public init(router: NativePacketRouter) throws {
        self.router = router
    }

    deinit {
        stop()
    }

    @discardableResult
    public func start(fileDescriptor: Int32, interfaceName: String) throws -> String {
        guard fileDescriptor >= 0 else {
            throw NativeTunnelError.invalidDescriptor
        }
        stop()
        if let phys = Self.physicalInterfaceName, !phys.isEmpty {
            phys.withCString { hajimi_engine_notify_network_change(router.engineRef, $0) }
        }
        let rc = hajimi_engine_attach_utun_fd(router.engineRef, fileDescriptor, 4)
        guard rc == HAJIMI_ENGINE_OK else {
            Darwin.close(fileDescriptor)
            throw NativeTunnelError.attachFailed
        }
        lock.lock()
        self.ownedFd = fileDescriptor
        self.interfaceName = interfaceName
        lock.unlock()
        router.startTelemetryPolling()
        return interfaceName
    }

    public func waitUntilReaderReady(timeout: TimeInterval = 2) throws {
        _ = timeout
    }

    public func start() throws -> String {
        throw NativeTunnelError.unsupportedDirectCreation
    }

    public func stop() {
        router.stopTelemetryPolling()
        hajimi_engine_detach_utun_fd(router.engineRef)
        lock.lock()
        let fd = ownedFd
        ownedFd = -1
        interfaceName = nil
        lock.unlock()
        if fd >= 0 {
            Darwin.close(fd)
        }
    }

    public func statistics() -> NativeTunnelStatistics {
        guard let raw = hajimi_engine_get_status_json(router.engineRef) else {
            return NativeTunnelStatistics(activeFlows: 0, totalFlows: 0, uploadedBytes: 0, downloadedBytes: 0)
        }
        defer { hajimi_engine_free_string(raw) }
        guard let data = String(cString: raw).data(using: .utf8),
              let obj = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] else {
            return NativeTunnelStatistics(activeFlows: 0, totalFlows: 0, uploadedBytes: 0, downloadedBytes: 0)
        }
        let activeTcp = (obj["tunActiveTcpFlows"] as? Int) ?? (obj["activeTcpFlows"] as? Int) ?? 0
        let activeUdp = (obj["tunActiveUdpSessions"] as? Int) ?? (obj["activeUdpSessions"] as? Int) ?? 0
        let totalTcp = (obj["tunTotalTcpFlows"] as? Int) ?? (obj["totalTcpFlows"] as? Int) ?? 0
        let totalUdp = (obj["tunTotalUdpSessions"] as? Int) ?? (obj["totalUdpSessions"] as? Int) ?? 0
        let up = (obj["uploadedBytes"] as? NSNumber)?.uint64Value ?? 0
        let down = (obj["downloadedBytes"] as? NSNumber)?.uint64Value ?? 0
        return NativeTunnelStatistics(
            activeFlows: activeTcp + activeUdp,
            totalFlows: totalTcp + totalUdp,
            uploadedBytes: up,
            downloadedBytes: down
        )
    }

    public func resetFlows() {
        _ = hajimi_engine_close_connection(router.engineRef, 0)
    }
}
