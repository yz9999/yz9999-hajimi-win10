#include "HajimiWinTransportCXX.h"
#include "HajimiProtocolsCXX.h"
#include "ServerProtocols.hpp"
#include "PlatformCompat.hpp"

#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <thread>

int main() {
    const int transportCode = hajimi_win_transport_self_test();
    if (transportCode != 0) {
        std::fprintf(stderr, "HajimiWinTransportCXX self-test failed at step %d\n", transportCode);
        return 1;
    }

    const int protoCode = hajimi_cpp_protocol_self_test();
    if (protoCode != 0) {
        std::fprintf(stderr, "HajimiProtocolsCXX self-test failed with code %d\n", protoCode);
        return 2;
    }

    // End-to-end integration check: dial HajimiProtocolsCXX SOCKS5 client through
    // live WinTransportRuntime sockets against Hajimi's C++ acceptSOCKS5 server!
    using namespace hajimi;
    using namespace hajimi::win_transport;

    platform::ensureWinsock();
    platform::NativeSocket socksListener = platform::toNativeSocket(::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP));
    if (socksListener < 0) return 3;
    sockaddr_in bindAddr{};
    bindAddr.sin_family = AF_INET;
    bindAddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    socklen_t bindLen = sizeof(bindAddr);
    if (::bind(platform::toOsSocket(socksListener), reinterpret_cast<sockaddr *>(&bindAddr), bindLen) != 0 ||
        ::getsockname(platform::toOsSocket(socksListener), reinterpret_cast<sockaddr *>(&bindAddr), &bindLen) != 0 ||
        ::listen(platform::toOsSocket(socksListener), 2) != 0) {
        platform::closeNativeSocket(socksListener);
        return 4;
    }
    const uint16_t socksPort = ntohs(bindAddr.sin_port);

    class BlockingSocketStream final : public Stream {
        platform::NativeSocket s_;
    public:
        explicit BlockingSocketStream(platform::NativeSocket s) : s_(s) {}
        ~BlockingSocketStream() override { close(); }
        void write(Buffer data, WriteCallback cb) override {
            size_t off = 0;
            while (off < data.size()) {
                ssize_t n = ::send(platform::toOsSocket(s_),
                                   reinterpret_cast<const char *>(data.data() + off),
                                   static_cast<int>(data.size() - off), 0);
                if (n <= 0) { cb("Server write failed"); return; }
                off += static_cast<size_t>(n);
            }
            cb({});
        }
        void read(size_t maxBytes, ReadCallback cb) override {
            Buffer buf(maxBytes);
            ssize_t n = ::recv(platform::toOsSocket(s_), reinterpret_cast<char *>(buf.data()),
                               static_cast<int>(buf.size()), 0);
            if (n < 0) { cb({}, true, "Server read failed"); return; }
            buf.resize(static_cast<size_t>(n));
            cb(std::move(buf), n == 0, {});
        }
        void close() override { platform::closeNativeSocket(s_); }
    };

    auto srvRuntime = WinTransportRuntime::create();
    auto srvFactory = srvRuntime->makeFactory();

    std::thread serverThread([socksListener, srvFactory] {
        platform::NativeSocket accepted = platform::toNativeSocket(
            ::accept(platform::toOsSocket(socksListener), nullptr, nullptr));
        platform::NativeSocket ownedListener = socksListener;
        platform::closeNativeSocket(ownedListener);
        if (accepted < 0) return;

        auto raw = std::make_shared<BlockingSocketStream>(accepted);
        srvFactory->post([raw, srvFactory] {
            acceptSOCKS5(raw, srvFactory, [raw](Target target, uint8_t command, Buffer initial, Error err) {
                if (!err.empty() || command != 1 || target.host != "win-e2e.example.com" || target.port != 8443) {
                    raw->close();
                    return;
                }
                Buffer rep = socksReply(0x00, {"127.0.0.1", 0, false, false});
                raw->write(std::move(rep), [raw, initial = std::move(initial)](Error werr) mutable {
                    if (!werr.empty()) { raw->close(); return; }
                    if (!initial.empty()) {
                        raw->write(std::move(initial), [raw](Error) { raw->close(); });
                        return;
                    }
                    raw->read(4096, [raw](Buffer payload, bool, Error rerr) {
                        if (rerr.empty() && !payload.empty()) {
                            raw->write(std::move(payload), [raw](Error) { raw->close(); });
                        } else {
                            raw->close();
                        }
                    });
                });
            });
        });
    });

    auto rt = WinTransportRuntime::create();
    auto factory = rt->makeFactory();
    Node clientNode;
    clientNode.type = "socks5";
    clientNode.host = "127.0.0.1";
    clientNode.connectHost = "127.0.0.1";
    clientNode.port = socksPort;

    std::mutex m;
    std::condition_variable cv;
    bool e2eDone = false;
    bool e2eOk = false;
    const Buffer probe{'h', 'a', 'j', 'i', 'm', 'i', '-', 'w', 'i', 'n', '-', 'e', '2', 'e'};

    factory->post([&] {
        connectProtocol(clientNode, {"win-e2e.example.com", 8443, false, false}, factory,
            [&](std::shared_ptr<Stream> stream, Error err) {
                if (!err.empty() || !stream) {
                    std::lock_guard<std::mutex> g(m); e2eDone = true; cv.notify_all(); return;
                }
                stream->write(probe, [&, stream](Error werr) {
                    if (!werr.empty()) {
                        std::lock_guard<std::mutex> g(m); e2eDone = true; cv.notify_all(); return;
                    }
                    stream->read(4096, [&, stream](Buffer reply, bool, Error rerr) {
                        std::lock_guard<std::mutex> g(m);
                        e2eOk = (rerr.empty() && reply == probe);
                        stream->close();
                        e2eDone = true;
                        cv.notify_all();
                    });
                });
            });
    });

    {
        std::unique_lock<std::mutex> u(m);
        if (!cv.wait_for(u, std::chrono::seconds(8), [&] { return e2eDone; })) e2eOk = false;
    }
    serverThread.join();
    rt->shutdown();
    srvRuntime->shutdown();

    if (!e2eOk) {
        std::fprintf(stderr, "End-to-end WinTransportRuntime + SOCKS5 loopback check failed\n");
        return 5;
    }

    std::puts("HajimiWinTransportCXX: strand, TCP 128KiB batch/half-close, UDP 10054-guard, TLS 1.3 UTF-8 CA/system trust & E2E passed");
    return 0;
}
