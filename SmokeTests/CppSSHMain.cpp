#include "SSH.hpp"
#include "Crypto.hpp"
#include "PlatformCompat.hpp"
#include <algorithm>
#include <cassert>
#include <cerrno>
#include <chrono>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <queue>
#include <sstream>
#include <stdexcept>
#include <utility>

using namespace hajimi;
namespace {
class SocketStream;
struct Loop {
    using Clock = std::chrono::steady_clock;
    struct Timer { Clock::time_point due; std::function<void()> work; };
    std::queue<std::function<void()>> work;
    std::vector<Timer> timers;
    std::vector<std::weak_ptr<SocketStream>> sockets;
    void post(std::function<void()> next) { work.push(std::move(next)); }
    void after(double seconds, std::function<void()> next) { timers.push_back({Clock::now() + std::chrono::milliseconds(int(seconds * 1000)), std::move(next)}); }
    void drain() {
        size_t count = 0;
        while (!work.empty()) { assert(++count < 1000000); auto next = std::move(work.front()); work.pop(); next(); }
    }
    void until(const std::function<bool()> &done, double seconds = 15);
};
class SocketStream final : public Stream, public std::enable_shared_from_this<SocketStream> {
public:
    SocketStream(Loop &loop, platform::NativeSocket descriptor) : loop_(loop), descriptor_(descriptor) {}
    ~SocketStream() override { close(); }
    size_t sentBytes = 0;
    platform::NativeSocket descriptor() const { return descriptor_; }
#if defined(_WIN32)
    SHORT events() const { return SHORT((pendingRead_ ? POLLRDNORM : 0) | (pendingWrite_ ? POLLWRNORM : 0)); }
#else
    short events() const { return short((pendingRead_ ? POLLIN : 0) | (pendingWrite_ ? POLLOUT : 0)); }
#endif
    void write(Buffer data, WriteCallback completion) override {
        assert(!pendingWrite_); if (descriptor_ < 0) { completion("Test carrier closed"); return; }
        output_ = std::move(data); offset_ = 0; pendingWrite_ = std::move(completion);
    }
    void read(size_t maximum, ReadCallback completion) override {
        assert(!pendingRead_); if (descriptor_ < 0) { completion({}, true, "Test carrier closed"); return; }
        maximum_ = maximum; pendingRead_ = std::move(completion);
    }
    void close() override {
        platform::closeNativeSocket(descriptor_);
        if (auto callback = std::exchange(pendingWrite_, {})) loop_.post([callback = std::move(callback)] { callback("Test carrier closed"); });
        if (auto callback = std::exchange(pendingRead_, {})) loop_.post([callback = std::move(callback)] { callback({}, true, "Test carrier closed"); });
    }
    void tick(short events) {
        if (descriptor_ < 0) return;
        if (pendingWrite_ && (events & (POLLOUT | POLLERR | POLLHUP))) {
            ssize_t count = ::send(platform::toOsSocket(descriptor_),
                                   reinterpret_cast<const char *>(output_.data() + offset_),
                                   static_cast<int>(output_.size() - offset_), 0);
            int err = count < 0 ? platform::lastSocketError() : 0;
            if (count < 0 && !platform::isSocketWouldBlock(err)) {
                std::fprintf(stderr, "SSH fixture TCP send failed: err=%d, queued=%zu, sent=%zu\n", err, output_.size() - offset_, sentBytes);
                close(); return;
            }
            if (count > 0) { offset_ += size_t(count); sentBytes += size_t(count); }
            if (offset_ == output_.size()) {
                output_.clear(); offset_ = 0; auto callback = std::exchange(pendingWrite_, {});
                loop_.post([callback = std::move(callback)] { callback({}); });
            }
        }
        if (pendingRead_ && (events & (POLLIN | POLLERR | POLLHUP))) {
            Buffer data(maximum_);
            ssize_t count = ::recv(platform::toOsSocket(descriptor_),
                                   reinterpret_cast<char *>(data.data()),
                                   static_cast<int>(data.size()), 0);
            int err = count < 0 ? platform::lastSocketError() : 0;
            if (count < 0 && platform::isSocketWouldBlock(err)) return;
            if (count < 0) { close(); return; }
            data.resize(size_t(count)); auto callback = std::exchange(pendingRead_, {});
            loop_.post([callback = std::move(callback), data = std::move(data), count]() mutable { callback(std::move(data), !count, {}); });
        }
    }
private:
    Loop &loop_;
    platform::NativeSocket descriptor_;
    Buffer output_;
    size_t offset_ = 0, maximum_ = 0;
    WriteCallback pendingWrite_;
    ReadCallback pendingRead_;
};
void Loop::until(const std::function<bool()> &done, double seconds) {
    auto deadline = Clock::now() + std::chrono::milliseconds(int(seconds * 1000));
    while (!done()) {
        drain(); if (done()) break;
        assert(Clock::now() < deadline);
        auto now = Clock::now();
        for (auto &timer : timers) if (timer.work && timer.due <= now) { post(std::exchange(timer.work, {})); }
#if defined(_WIN32)
        std::vector<WSAPOLLFD> descriptors;
        std::vector<std::shared_ptr<SocketStream>> sources;
        for (const auto &weak : sockets) if (auto source = weak.lock(); source && source->descriptor() >= 0 && source->events()) {
            descriptors.push_back({platform::toOsSocket(source->descriptor()), source->events(), 0});
            sources.push_back(std::move(source));
        }
        if (!descriptors.empty()) {
            int code = ::WSAPoll(descriptors.data(), static_cast<ULONG>(descriptors.size()), 10);
            assert(code != SOCKET_ERROR || platform::lastSocketError() == WSAEINTR);
            for (size_t i = 0; i < descriptors.size(); ++i) if (descriptors[i].revents) sources[i]->tick(descriptors[i].revents);
        } else {
            ::Sleep(5);
        }
#else
        std::vector<pollfd> descriptors; std::vector<std::shared_ptr<SocketStream>> sources;
        for (const auto &weak : sockets) if (auto source = weak.lock(); source && source->descriptor() >= 0 && source->events()) {
            descriptors.push_back({source->descriptor(), source->events(), 0}); sources.push_back(std::move(source));
        }
        int code = ::poll(descriptors.data(), descriptors.size(), 10); assert(code >= 0 || errno == EINTR);
        for (size_t i = 0; i < descriptors.size(); ++i) if (descriptors[i].revents) sources[i]->tick(descriptors[i].revents);
#endif
    }
    drain();
}
std::shared_ptr<TransportFactory> makeFactory(Loop &loop) {
    platform::ensureWinsock();
    auto factory = std::make_shared<TransportFactory>();
    factory->post = [&loop](std::function<void()> work) { loop.post(std::move(work)); };
    factory->after = [&loop](double seconds, std::function<void()> work) { loop.after(seconds, std::move(work)); };
    factory->tcp = [&loop](const Node &node, const TLSOptions &tls, StreamCallback completion) {
        assert(node.host == "127.0.0.1" && !tls.enabled);
        platform::NativeSocket descriptor = platform::toNativeSocket(::socket(AF_INET, SOCK_STREAM, 0));
        assert(descriptor >= 0);
        sockaddr_in address{}; address.sin_family = AF_INET; address.sin_port = htons(node.port); address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        if (::connect(platform::toOsSocket(descriptor), reinterpret_cast<sockaddr *>(&address), sizeof(address))) {
            platform::closeNativeSocket(descriptor); completion({}, "Fixture TCP connect failed"); return;
        }
        assert(platform::setNonBlockingAndCloexec(descriptor));
#ifdef SO_NOSIGPIPE
        int enabled = 1; assert(!setsockopt(descriptor, SOL_SOCKET, SO_NOSIGPIPE, &enabled, sizeof(enabled)));
#endif
        auto stream = std::make_shared<SocketStream>(loop, descriptor); loop.sockets.push_back(stream);
        loop.post([stream, completion = std::move(completion)] { completion(stream, {}); });
    };
    return factory;
}
Buffer bytes(const std::string &text) { return Buffer(text.begin(), text.end()); }
class BlackholeStream final : public Stream {
public:
    explicit BlackholeStream(Loop &loop) : loop_(loop) {}
    void write(Buffer, WriteCallback completion) override { loop_.post([completion = std::move(completion)] { completion({}); }); }
    void read(size_t, ReadCallback completion) override { assert(!pending_); pending_ = std::move(completion); }
    void close() override {
        if (auto completion = std::exchange(pending_, {})) loop_.post([completion = std::move(completion)] { completion({}, true, {}); });
    }
private:
    Loop &loop_;
    ReadCallback pending_;
};
} // namespace

int main(int argc, char **argv) {
    if (argc != 7) { std::fputs("Run through SmokeTests/cpp_ssh_interop.py for the local SSH fixture.\n", stderr); return 2; }
    unsigned port = unsigned(std::stoul(argv[1])); assert(port && port <= 65535);
    Node node; node.type = "ssh"; node.host = "127.0.0.1"; node.port = uint16_t(port);
    node.parameters["username"] = "fixture-user"; node.parameters["password"] = "fixture-password"; node.parameters["host-key"] = argv[2];
    assert(validateSSH(node, false).empty() && !validateSSH(node, true).empty());
    Node insecure = node; insecure.parameters.erase("host-key"); assert(!validateSSH(insecure, false).empty());
    insecure.parameters["skip-cert-verify"] = "true"; assert(validateSSH(insecure, false).empty());
    Node partial = insecure; partial.parameters.erase("skip-cert-verify"); partial.parameters["skip-common-name-verify"] = "true";
    assert(!validateSSH(partial, false).empty());
    Node unsupported = node; unsupported.parameters["host-key-algorithms"] = "not-a-real-ssh-key-algorithm"; assert(!validateSSH(unsupported, false).empty());
    Node missingKey = node; missingKey.parameters["private-key"] = "fixture-file-that-does-not-exist";
    assert(validateSSH(missingKey, false).empty()); // Support checks are pure configuration validation.
    std::istringstream keyText(argv[3]); std::string keyType, encoded; keyText >> keyType >> encoded;
    auto wireKey = crypto::base64Decode(encoded); assert(ssh::hostKeyMatches(node, wireKey));
    Node authorized = node; authorized.parameters["host-key"] = argv[3]; assert(ssh::hostKeyMatches(authorized, wireKey));
    Node wrongPin = node; wrongPin.parameters["host-key"] = "SHA256:" + crypto::base64Encode(Buffer(32, 0));
    wrongPin.parameters["skip-cert-verify"] = "true"; assert(!ssh::hostKeyMatches(wrongPin, wireKey));

    Loop loop; auto factory = makeFactory(loop); Target target{"target.test", 443, false, false};
    {
        namespace fs = std::filesystem;
        const auto rb = crypto::randomBytes(6);
        char randSuffix[13]{};
        for (size_t i = 0; i < rb.size(); ++i) {
            std::snprintf(randSuffix + i * 2, 3, "%02x", rb[i]);
        }
        fs::path tempDir = fs::temp_directory_path() / (std::string("hajimi-ssh-boundary-") + randSuffix);
        assert(fs::create_directories(tempDir));
        struct Cleanup {
            fs::path dir;
            ~Cleanup() { std::error_code ec; fs::remove_all(dir, ec); }
        } cleanup{tempDir};
        auto file = [&](const std::string &name, size_t size) {
            fs::path p = cleanup.dir / name;
            std::ofstream out(p, std::ios::binary | std::ios::trunc);
            assert(bool(out));
            if (size > 0) {
                std::string zeros(size, 'x');
                out.write(zeros.data(), static_cast<std::streamsize>(zeros.size()));
            }
            out.close();
        };
        file("empty", 0); file("oversize", 256 * 1024 + 1); file("invalid", 100);
#if !defined(_WIN32)
        assert(!::mkfifo((cleanup.dir / "fifo").string().c_str(), 0600));
        assert(!::symlink((cleanup.dir / "fifo").string().c_str(), (cleanup.dir / "fifo-link").string().c_str()));
#endif
        auto probe = std::make_shared<TransportFactory>(); unsigned dials = 0;
        probe->post = factory->post; probe->after = factory->after;
        probe->tcp = [&](const Node &, const TLSOptions &, StreamCallback done) {
            ++dials; done({}, "Unexpected dial before private-key validation");
        };
        auto failBeforeDial = [&](const std::string &path, const std::string &expected) {
            Node selected = node; selected.parameters["private-key"] = path;
            assert(validateSSH(selected, false).empty());
            auto started = std::chrono::steady_clock::now();
            unsigned callbacks = 0; Error result;
            connectSSH(selected, target, probe, [&](std::shared_ptr<Stream> stream, Error error) {
                assert(!stream); ++callbacks; result = std::move(error);
            });
            loop.drain();
            assert(callbacks == 1 && dials == 0 && result.find(expected) != std::string::npos);
            assert(std::chrono::steady_clock::now() - started < std::chrono::milliseconds(500));
        };
        auto started = std::chrono::steady_clock::now();
        Node fastCheck = node; fastCheck.parameters["private-key"] = (cleanup.dir / "missing").u8string();
        for (unsigned i = 0; i < 1000; ++i) assert(validateSSH(fastCheck, false).empty());
        assert(std::chrono::steady_clock::now() - started < std::chrono::milliseconds(500));
        failBeforeDial((cleanup.dir / "missing").u8string(), "Cannot read");
#if !defined(_WIN32)
        failBeforeDial((cleanup.dir / "fifo").u8string(), "regular file");
        failBeforeDial((cleanup.dir / "fifo-link").u8string(), "regular file");
#else
        failBeforeDial("\\\\.\\NUL", "regular file");
#endif
        failBeforeDial(cleanup.dir.u8string(), "regular file");
        failBeforeDial((cleanup.dir / "empty").u8string(), "empty");
        failBeforeDial((cleanup.dir / "oversize").u8string(), "bound");
        failBeforeDial((cleanup.dir / "invalid").u8string(), "not PEM");
        Node bounded = node; bounded.parameters["private-key"] = std::string(256 * 1024 + 1, 'x');
        assert(!validateSSH(bounded, false).empty());
        bounded.parameters["private-key"] = std::string("key\0path", 8);
        assert(!validateSSH(bounded, false).empty());
    }
    unsigned rounds = 0;
    auto roundTrip = [&](Node selected) {
        std::shared_ptr<Stream> stream; bool done = false;
        connectSSH(selected, target, factory, [&](std::shared_ptr<Stream> connected, Error error) {
            if (!error.empty()) std::fprintf(stderr, "SSH fixture positive path failed: %s\n", error.c_str());
            assert(error.empty() && connected); stream = std::move(connected); done = true;
        });
        loop.until([&] { return done; }); assert(stream->supportsHalfClose());
        Buffer payload(350001); for (size_t i = 0; i < payload.size(); ++i) payload[i] = uint8_t(i + rounds);
        Buffer received; unsigned writes = 0; bool eof = false, halfClosed = false, overflow = false, duplicateRead = false;
        stream->write(Buffer(payload.begin(), payload.begin() + 190000), [&](Error error) { assert(error.empty()); ++writes; });
        stream->write(Buffer(payload.begin() + 190000, payload.end()), [&](Error error) { assert(error.empty()); ++writes; });
        stream->write(Buffer(maximumQueuedBytes + 1, 0), [&](Error error) { overflow = !error.empty(); });
        stream->shutdownWrite([&](Error error) { assert(error.empty()); halfClosed = true; });
        std::function<void()> more;
        more = [&] {
            stream->read(1023, [&](Buffer data, bool end, Error error) {
                if (!error.empty()) std::fprintf(stderr, "SSH fixture read failed: round=%u, received=%zu/%zu, error=%s\n",
                                                 rounds + 1, received.size(), payload.size(), error.c_str());
                assert(error.empty()); received.insert(received.end(), data.begin(), data.end()); eof = end; if (!eof) more();
            });
        };
        more(); stream->read(1, [&](Buffer, bool, Error error) { duplicateRead = !error.empty(); });
        loop.until([&] { return eof && halfClosed && writes == 2 && overflow && duplicateRead; });
        assert(received == payload); more = {};
        bool lateWrite = false; stream->write(bytes("after EOF"), [&](Error error) { lateWrite = !error.empty(); });
        loop.drain(); assert(lateWrite);
        std::weak_ptr<Stream> weak = stream; stream->close(); stream.reset(); loop.drain(); assert(weak.expired()); ++rounds;
    };
    roundTrip(node); roundTrip(authorized);
    Node privateKey = node; privateKey.parameters.erase("password"); privateKey.parameters["private-key"] = argv[4];
    privateKey.parameters["host-key-algorithms"] = "rsa-sha2-512|rsa-sha2-256"; roundTrip(privateKey);
    std::ifstream pem(argv[4], std::ios::binary); std::string inlineKey((std::istreambuf_iterator<char>(pem)), {});
    std::string escaped; for (char ch : inlineKey) escaped += ch == '\n' ? "\\n" : std::string(1, ch);
    privateKey.parameters["private-key"] = escaped; roundTrip(privateKey);
    privateKey.parameters["private-key"] = argv[5]; privateKey.parameters["private-key-passphrase"] = "fixture-passphrase"; roundTrip(privateKey);
    privateKey.parameters["private-key"] = argv[6]; privateKey.parameters.erase("private-key-passphrase"); roundTrip(privateKey);

    // Cancel while native wire packets are already draining, not only after EOF.
    std::shared_ptr<Stream> canceled; bool cancellationConnected = false;
    connectSSH(node, target, factory, [&](std::shared_ptr<Stream> stream, Error error) {
        assert(error.empty()); canceled = std::move(stream); cancellationConnected = true;
    }); loop.until([&] { return cancellationConnected; });
    auto raw = loop.sockets.back().lock(); assert(raw); size_t baseline = raw->sentBytes;
    unsigned canceledWrites = 0, canceledReads = 0;
    canceled->write(Buffer(1024 * 1024, 0x71), [&](Error error) { assert(!error.empty()); ++canceledWrites; });
    loop.until([&] { return raw->sentBytes > baseline; }); assert(canceledWrites == 0);
    canceled->read(1024, [&](Buffer, bool eof, Error error) { assert(eof && !error.empty()); ++canceledReads; });
    std::weak_ptr<Stream> canceledWeak = canceled; canceled->close(); canceled.reset(); loop.drain();
    assert(canceledWeak.expired() && canceledWrites == 1 && canceledReads == 1);

    auto failure = [&](Node selected, Target destination, const std::string &expected) {
        unsigned callbacks = 0; Error result;
        connectSSH(selected, destination, factory, [&](std::shared_ptr<Stream> stream, Error error) {
            assert(!stream && !error.empty()); ++callbacks; result = std::move(error);
        }); loop.until([&] { return callbacks != 0; }); assert(callbacks == 1 && result.find(expected) != std::string::npos);
        assert(result.find("fixture-password") == std::string::npos && result.find("fixture-passphrase") == std::string::npos);
    };
    failure(wrongPin, target, "host-key pin mismatch");
    Node wrongPassword = node; wrongPassword.parameters["password"] = "wrong-fixture-password";
    failure(wrongPassword, target, "authentication failed");
    failure(node, Target{"reject.test", 443, false, false}, "direct-tcpip request failed");
    Node wrongPassphrase = privateKey; wrongPassphrase.parameters["private-key"] = argv[5];
    wrongPassphrase.parameters["private-key-passphrase"] = "wrong-fixture-passphrase";
    failure(wrongPassphrase, target, "private-key authentication failed");

    auto blackhole = std::make_shared<BlackholeStream>(loop); auto blackFactory = std::make_shared<TransportFactory>();
    blackFactory->post = factory->post; blackFactory->after = factory->after;
    blackFactory->tcp = [&loop, blackhole](const Node &, const TLSOptions &, StreamCallback completion) {
        loop.post([blackhole, completion = std::move(completion)] { completion(blackhole, {}); });
    };
    unsigned timeoutCallbacks = 0;
    connectSSH(node, target, blackFactory, [&](std::shared_ptr<Stream> stream, Error error) {
        assert(!stream && error.find("timed out") != std::string::npos); ++timeoutCallbacks;
    }); loop.drain(); assert(!timeoutCallbacks && loop.timers.back().work);
    auto timeout = std::exchange(loop.timers.back().work, {}); timeout(); loop.drain(); assert(timeoutCallbacks == 1);
    timeout(); loop.drain(); assert(timeoutCallbacks == 1);
    std::puts("C++ SSH: pinned identities, password/RSA/PEM/OpenSSH/Ed25519 auth, TCP data, half-close, and negative paths passed");
}
