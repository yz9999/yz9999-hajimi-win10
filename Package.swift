// swift-tools-version: 5.9
import PackageDescription
import Foundation

let packageRoot = URL(fileURLWithPath: #filePath).deletingLastPathComponent().path
let nativeQUICPrefix = packageRoot + "/.build/Vendor/HajimiQUIC"
let nativeSSHPrefix = packageRoot + "/.build/Vendor/HajimiSSH"
let vendorAWSLC = packageRoot + "/.build/Vendor/AWSLC"
let vendorOpenSSL = packageRoot + "/.build/Vendor/OpenSSL"
let vendorIncludeDir = packageRoot + "/Sources/HajimiProtocolsCXX/VendorInclude"
let protocolsInternalDir = packageRoot + "/Sources/HajimiProtocolsCXX"

let useAWSLC: Bool = {
    if let envBackend = ProcessInfo.processInfo.environment["HAJIMI_TLS_BACKEND"]?.lowercased() {
        if envBackend == "awslc" { return true }
        if envBackend == "openssl" { return false }
    }
    if FileManager.default.fileExists(atPath: vendorOpenSSL + "/include/openssl/ssl.h") &&
       FileManager.default.fileExists(atPath: vendorOpenSSL + "/lib/libcrypto.a") {
        return false
    }
    return FileManager.default.fileExists(atPath: vendorAWSLC + "/include/openssl/ssl.h") &&
           FileManager.default.fileExists(atPath: vendorAWSLC + "/lib/libcrypto.a") &&
           FileManager.default.fileExists(atPath: nativeQUICPrefix + "/lib/libngtcp2_crypto_boringssl.a")
}()

let activeTLSRoot: String = {
    if useAWSLC {
        return vendorAWSLC
    }
    let candidates = [
        ProcessInfo.processInfo.environment["HAJIMI_OPENSSL_ROOT"],
        vendorOpenSSL,
        "/opt/homebrew/opt/openssl@3",
        "/usr/local/opt/openssl@3"
    ].compactMap { $0 }
    for candidate in candidates {
        if FileManager.default.fileExists(atPath: candidate + "/include/openssl/ssl.h") &&
           FileManager.default.fileExists(atPath: candidate + "/lib/libcrypto.a") {
            return candidate
        }
    }
    return vendorOpenSSL
}()

let nativeProtocolIncludes: [String] = {
    var flags: [String] = ["-I" + protocolsInternalDir]
    if !useAWSLC {
        flags.append("-I" + vendorIncludeDir)
    }
    flags.append("-I" + activeTLSRoot + "/include")
    flags.append("-I" + nativeQUICPrefix + "/include")
    flags.append("-I" + nativeSSHPrefix + "/include")
    if useAWSLC {
        flags.append("-DOPENSSL_IS_AWSLC=1")
    }
    return flags
}()

let ngtcp2CryptoLib = useAWSLC
    ? (nativeQUICPrefix + "/lib/libngtcp2_crypto_boringssl.a")
    : (nativeQUICPrefix + "/lib/libngtcp2_crypto_ossl.a")

let nativeProtocolLibraries: [String] = [
    ngtcp2CryptoLib,
    nativeQUICPrefix + "/lib/libngtcp2.a",
    nativeQUICPrefix + "/lib/libnghttp3.a",
    nativeSSHPrefix + "/lib/libssh2.a",
    activeTLSRoot + "/lib/libssl.a",
    activeTLSRoot + "/lib/libcrypto.a"
]

let package = Package(
    name: "Hajimi",
    platforms: [.macOS(.v13)],
    products: [
        .library(name: "HajimiCore", targets: ["HajimiCore"]),
        .library(name: "HajimiRuntime", targets: ["HajimiRuntime"]),
        .library(name: "HajimiUIComponents", targets: ["HajimiUIComponents"]),
        .library(name: "HajimiDiagnosticsUI", targets: ["HajimiDiagnosticsUI"]),
        .library(name: "HajimiIPC", targets: ["HajimiIPC"]),
        .library(name: "HajimiNativeCore", targets: ["HajimiNativeCore"]),
        .executable(name: "Hajimi", targets: ["HajimiApp"]),
        .executable(name: "HajimiHelper", targets: ["HajimiHelper"])
    ],
    dependencies: [],
    targets: [
        // ====================================================================
        // Unified Cross-Platform C11 / C++17 Data-Plane & Engine Core
        // (Shared 100% between macOS & Windows)
        // ====================================================================
        .target(
            name: "HajimiPlatformC",
            path: "Sources/HajimiPlatformC",
            publicHeadersPath: "include"
        ),
        .target(
            name: "HajimiDataPlaneC",
            path: "Sources/HajimiDataPlaneC",
            publicHeadersPath: "include"
        ),
        .target(
            name: "HajimiFlowCXX",
            path: "Sources/HajimiFlowCXX",
            publicHeadersPath: "include"
        ),
        .target(
            name: "HajimiRoutingCXX",
            path: "Sources/HajimiRoutingCXX",
            publicHeadersPath: "include"
        ),
        .target(
            name: "HajimiProtocolCXX",
            path: "Sources/HajimiProtocolCXX",
            publicHeadersPath: "include",
            cxxSettings: [.unsafeFlags(["-fno-exceptions", "-fno-rtti"])]
        ),
        .target(
            name: "HajimiProtocolsCXX",
            dependencies: ["HajimiProtocolCXX", "HajimiPlatformC"],
            path: "Sources/HajimiProtocolsCXX",
            publicHeadersPath: "include",
            cxxSettings: [
                .define("__APPLE_USE_RFC_3542", .when(platforms: [.macOS, .iOS])),
                .define("NGTCP2_STATICLIB"),
                .define("NGHTTP3_STATICLIB"),
                .unsafeFlags(nativeProtocolIncludes)
            ],
            linkerSettings: [
                .unsafeFlags(nativeProtocolLibraries),
                .linkedFramework("Security"),
                .linkedFramework("CoreFoundation")
            ]
        ),
        .target(
            name: "HajimiWinTransportCXX",
            dependencies: ["HajimiProtocolsCXX", "HajimiPlatformC"],
            path: "Sources/HajimiWinTransportCXX",
            publicHeadersPath: "include",
            cxxSettings: [
                .define("__APPLE_USE_RFC_3542", .when(platforms: [.macOS, .iOS])),
                .unsafeFlags(nativeProtocolIncludes)
            ],
            linkerSettings: [
                .linkedFramework("Security"),
                .linkedFramework("CoreFoundation")
            ]
        ),
        .target(
            name: "HajimiEngineCAPI",
            dependencies: [
                "HajimiPlatformC",
                "HajimiDataPlaneC",
                "HajimiFlowCXX",
                "HajimiRoutingCXX",
                "HajimiProtocolCXX",
                "HajimiProtocolsCXX",
                "HajimiWinTransportCXX"
            ],
            path: "Sources/HajimiEngineCAPI",
            publicHeadersPath: "include",
            cxxSettings: [
                .define("__APPLE_USE_RFC_3542", .when(platforms: [.macOS, .iOS])),
                .unsafeFlags(nativeProtocolIncludes)
            ],
            linkerSettings: [
                .linkedFramework("Security"),
                .linkedFramework("CoreFoundation"),
                .linkedFramework("SystemConfiguration")
            ]
        ),
        .target(
            name: "HajimiEngineCBridge",
            dependencies: ["HajimiEngineCAPI", "HajimiDataPlaneC"],
            path: "Sources/HajimiEngineCBridge",
            publicHeadersPath: "include"
        ),

        // ====================================================================
        // Thin macOS Native AppKit Shell & Privileged utun Helper
        // ====================================================================
        .target(
            name: "HajimiMacOSObjC",
            publicHeadersPath: "include",
            cSettings: [.unsafeFlags(["-fobjc-arc"])],
            linkerSettings: [
                .linkedFramework("AppKit"),
                .linkedFramework("NetworkExtension"),
                .linkedFramework("Security")
            ]
        ),
        .target(name: "HajimiIPC"),
        .target(name: "HajimiRuntime"),
        .target(name: "HajimiUIComponents"),
        .target(
            name: "HajimiCore",
            dependencies: ["HajimiEngineCBridge", "HajimiRoutingCXX", "HajimiProtocolCXX"]
        ),
        .target(
            name: "HajimiNativeCore",
            dependencies: ["HajimiCore", "HajimiEngineCBridge"]
        ),
        .target(
            name: "HajimiDiagnosticsUI",
            dependencies: ["HajimiCore", "HajimiRuntime", "HajimiUIComponents"]
        ),
        .executableTarget(
            name: "HajimiApp",
            dependencies: [
                "HajimiCore",
                "HajimiIPC",
                "HajimiNativeCore",
                "HajimiMacOSObjC",
                "HajimiRuntime",
                "HajimiUIComponents",
                "HajimiDiagnosticsUI"
            ],
            swiftSettings: [.define("HAJIMI_MINIMAL_RELEASE")]
        ),
        .executableTarget(
            name: "HajimiHelper",
            dependencies: ["HajimiIPC"]
        )
    ],
    cxxLanguageStandard: .cxx17
)
