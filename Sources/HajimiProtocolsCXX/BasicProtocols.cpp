#include "BasicProtocols.hpp"
#include "Crypto.hpp"
#include "HttpProxyProtocol.hpp"
#include "ProtocolCommon.hpp"
#include "ProtocolStream.hpp"
#include "Socks5Protocol.hpp"
#include "VlessTrojanProtocol.hpp"
#include <algorithm>
#include <cctype>
#include <cstring>
#include <deque>
#include <sstream>
#include <stdexcept>
#include <unordered_map>

namespace hajimi {

namespace {

bool nodeUsesWebSocket(const Node &node) {
    if (node.flag("ws", false)) return true;
    std::string net = node.option("network");
    std::transform(net.begin(), net.end(), net.begin(), [](unsigned char c) { return char(std::tolower(c)); });
    return net == "ws" || net == "websocket";
}

std::string stripQuotesCopy(std::string s) {
    while (!s.empty() && std::isspace(static_cast<unsigned char>(s.front()))) s.erase(s.begin());
    while (!s.empty() && std::isspace(static_cast<unsigned char>(s.back()))) s.pop_back();
    if (s.size() >= 2 &&
        ((s.front() == '"' && s.back() == '"') || (s.front() == '\'' && s.back() == '\''))) {
        s = s.substr(1, s.size() - 2);
    }
    return s;
}

std::string resolveWebSocketHostHeader(const Node &node) {
    std::string h = stripQuotesCopy(node.option("ws-host"));
    if (!h.empty()) return h;
    std::string hdrs = node.option("ws-headers");
    if (!hdrs.empty()) {
        std::string low = hdrs;
        std::transform(low.begin(), low.end(), low.begin(), [](unsigned char c) { return char(std::tolower(c)); });
        auto pos = low.find("host:");
        if (pos != std::string::npos) {
            std::string val = hdrs.substr(pos + 5);
            auto sep = val.find_first_of("|\r\n;");
            if (sep != std::string::npos) val.resize(sep);
            h = stripQuotesCopy(val);
            if (!h.empty()) return h;
        }
    }
    h = stripQuotesCopy(node.option("sni", node.option("servername", node.host)));
    return h.empty() ? node.host : h;
}

/// RFC 6455 client WebSocket stream carrier (supports binary frames, client masking,
/// fragmented server frames, Ping/Pong keepalive, and Close handshake).
class WebSocketClientStream final : public Stream, public std::enable_shared_from_this<WebSocketClientStream> {
    std::shared_ptr<Stream> source_;
    std::shared_ptr<Reader> reader_;
    std::shared_ptr<OrderedWriter> writer_;
    proto_common::CursorBuffer rxWire_;
    proto_common::CursorBuffer rxApp_;
    ReadCallback pendingRead_;
    size_t readMax_ = 0;
    bool closed_ = false;
    bool eof_ = false;
    bool writeClosed_ = false;
    bool pumping_ = false;

    static Buffer buildMaskedFrame(uint8_t opcode, const uint8_t *payload, size_t len) {
        Buffer mask = crypto::randomBytes(4);
        Buffer frame;
        frame.reserve(14 + len);
        frame.push_back(static_cast<uint8_t>(0x80u | (opcode & 0x0Fu)));
        if (len < 126) {
            frame.push_back(static_cast<uint8_t>(0x80u | len));
        } else if (len <= 65535) {
            frame.push_back(static_cast<uint8_t>(0x80u | 126u));
            frame.push_back(static_cast<uint8_t>((len >> 8) & 0xFFu));
            frame.push_back(static_cast<uint8_t>(len & 0xFFu));
        } else {
            frame.push_back(static_cast<uint8_t>(0x80u | 127u));
            uint64_t u64Len = static_cast<uint64_t>(len);
            for (int shift = 56; shift >= 0; shift -= 8) {
                frame.push_back(static_cast<uint8_t>((u64Len >> shift) & 0xFFu));
            }
        }
        frame.insert(frame.end(), mask.begin(), mask.end());
        size_t base = frame.size();
        frame.resize(base + len);
        for (size_t i = 0; i < len; ++i) {
            frame[base + i] = payload[i] ^ mask[i & 3u];
        }
        return frame;
    }

    int tryDecodeFrames() {
        while (rxWire_.size() >= 2) {
            const uint8_t *p = rxWire_.data();
            const uint8_t b0 = p[0];
            const uint8_t b1 = p[1];
            const uint8_t opcode = b0 & 0x0Fu;
            const bool masked = (b1 & 0x80u) != 0;
            uint64_t payloadLen = b1 & 0x7Fu;
            size_t hdrLen = 2;
            if (payloadLen == 126) {
                if (rxWire_.size() < 4) return 0;
                payloadLen = (static_cast<uint64_t>(p[2]) << 8) | static_cast<uint64_t>(p[3]);
                hdrLen = 4;
            } else if (payloadLen == 127) {
                if (rxWire_.size() < 10) return 0;
                payloadLen = 0;
                for (int i = 2; i < 10; ++i) payloadLen = (payloadLen << 8) | static_cast<uint64_t>(p[i]);
                hdrLen = 10;
            }
            if (payloadLen > maximumQueuedBytes) return -1;
            const size_t maskLen = masked ? 4u : 0u;
            const size_t totalFrame = hdrLen + maskLen + static_cast<size_t>(payloadLen);
            if (rxWire_.size() < totalFrame) return 0;

            uint8_t maskKey[4]{};
            if (masked) std::memcpy(maskKey, p + hdrLen, 4);
            Buffer body = rxWire_.sliceAndAdvance(hdrLen + maskLen, static_cast<size_t>(payloadLen));
            if (masked) {
                for (size_t i = 0; i < body.size(); ++i) body[i] ^= maskKey[i & 3u];
            }

            if (opcode == 0x00u || opcode == 0x01u || opcode == 0x02u) {
                if (!body.empty()) rxApp_.append(body.data(), body.size());
            } else if (opcode == 0x08u) {
                eof_ = true;
                return 1;
            } else if (opcode == 0x09u) {
                if (!closed_ && !writeClosed_ && body.size() <= 125) {
                    writer_->write(buildMaskedFrame(0x0Au, body.data(), body.size()), [](Error) {});
                }
            }
        }
        return 0;
    }

    void satisfyRead() {
        if (!pendingRead_) return;
        if (!rxApp_.empty()) {
            size_t n = std::min(readMax_, rxApp_.size());
            Buffer chunk = rxApp_.consume(n);
            bool done = rxApp_.empty() && eof_;
            auto cb = std::move(pendingRead_);
            pendingRead_ = nullptr;
            cb(std::move(chunk), done, {});
            return;
        }
        if (eof_) {
            auto cb = std::move(pendingRead_);
            pendingRead_ = nullptr;
            cb({}, true, {});
            return;
        }
        pumpMore();
    }

    void failStream(Error err) {
        if (closed_) return;
        closed_ = true;
        writer_->close();
        reader_->close();
        rxWire_.clear();
        rxApp_.clear();
        if (auto cb = std::move(pendingRead_)) {
            pendingRead_ = nullptr;
            cb({}, true, err.empty() ? Error("WebSocket stream closed") : std::move(err));
        }
    }

    void pumpMore() {
        if (closed_ || eof_ || pumping_ || !pendingRead_) return;
        pumping_ = true;
        auto self = shared_from_this();
        reader_->some(65536, [self](Buffer data, bool rawEof, Error err) {
            self->pumping_ = false;
            if (self->closed_) return;
            if (!data.empty()) {
                self->rxWire_.append(data.data(), data.size());
                int st = self->tryDecodeFrames();
                if (st < 0) {
                    self->failStream("Malformed or oversized WebSocket frame");
                    return;
                }
            }
            if (!err.empty()) {
                if (!self->rxApp_.empty()) {
                    self->eof_ = true;
                    self->satisfyRead();
                } else {
                    self->failStream(std::move(err));
                }
                return;
            }
            if (rawEof) self->eof_ = true;
            self->satisfyRead();
        });
    }

public:
    WebSocketClientStream(std::shared_ptr<Stream> source,
                          std::shared_ptr<Reader> reader,
                          Buffer initialLeftover)
        : source_(std::move(source)),
          reader_(std::move(reader)),
          writer_(std::make_shared<OrderedWriter>(source_, maximumQueuedBytes, 128, proto_stream::kMaxCoalescedWriteBytes)) {
        if (!initialLeftover.empty()) {
            rxWire_.append(initialLeftover.data(), initialLeftover.size());
            if (tryDecodeFrames() < 0) {
                throw std::runtime_error("Invalid initial WebSocket frame after HTTP 101");
            }
        }
    }

    void write(Buffer data, WriteCallback completion) override {
        if (closed_ || writeClosed_) {
            completion("WebSocket write side closed");
            return;
        }
        if (data.empty()) {
            completion({});
            return;
        }
        constexpr size_t kMaxWsChunk = 32768;
        Buffer framed;
        framed.reserve(data.size() + ((data.size() + kMaxWsChunk - 1) / kMaxWsChunk) * 10);
        for (size_t off = 0; off < data.size(); off += kMaxWsChunk) {
            size_t n = std::min(kMaxWsChunk, data.size() - off);
            Buffer f = buildMaskedFrame(0x02u, data.data() + off, n);
            framed.insert(framed.end(), f.begin(), f.end());
        }
        if (!writer_->canAccept(framed.size())) {
            completion("WebSocket write queue limit exceeded");
            return;
        }
        writer_->write(std::move(framed), std::move(completion));
    }

    void read(size_t maximum, ReadCallback completion) override {
        if (closed_) {
            completion({}, true, "WebSocket stream closed");
            return;
        }
        if (pendingRead_ || maximum == 0 || maximum > maximumReadBytes) {
            completion({}, false, "Invalid or concurrent WebSocket read");
            return;
        }
        readMax_ = maximum;
        pendingRead_ = std::move(completion);
        satisfyRead();
    }

    void shutdownWrite(WriteCallback completion) override {
        if (closed_ || writeClosed_) {
            completion("WebSocket write side already closed");
            return;
        }
        writeClosed_ = true;
        Buffer closeFrame = buildMaskedFrame(0x08u, nullptr, 0);
        auto self = shared_from_this();
        writer_->write(std::move(closeFrame), [self, completion = std::move(completion)](Error err) mutable {
            if (!err.empty()) {
                completion(std::move(err));
                return;
            }
            if (self->source_->supportsHalfClose()) {
                self->writer_->finish(std::move(completion));
            } else {
                completion({});
            }
        });
    }

    bool supportsHalfClose() const override { return true; }

    void close() override {
        failStream("WebSocket stream closed");
    }
};

} // namespace

void upgradeWebSocketCarrierIfNeeded(const Node &node,
                                     std::shared_ptr<Stream> source,
                                     std::shared_ptr<TransportFactory>,
                                     StreamCallback completion) {
    if (!source) {
        completion(nullptr, "Null carrier stream");
        return;
    }
    if (!nodeUsesWebSocket(node)) {
        completion(std::move(source), {});
        return;
    }

    try {
        std::string wsPath = stripQuotesCopy(node.option("ws-path", "/"));
        if (wsPath.empty()) wsPath = "/";
        if (wsPath.front() != '/') wsPath.insert(wsPath.begin(), '/');
        // Strip Xray/Clash `?ed=...` query suffix if present so standard servers accept the request URI
        auto edPos = wsPath.find("?ed=");
        if (edPos != std::string::npos) {
            wsPath.resize(edPos);
            if (wsPath.empty()) wsPath = "/";
        } else {
            auto ampEd = wsPath.find("&ed=");
            if (ampEd != std::string::npos) wsPath.resize(ampEd);
        }

        const std::string hostHdr = resolveWebSocketHostHeader(node);
        const std::string wsKey = crypto::base64Encode(crypto::randomBytes(16));
        const std::string acceptMaterial = wsKey + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
        const std::string expectedAccept = crypto::base64Encode(
            crypto::digest("SHA1", Buffer(acceptMaterial.begin(), acceptMaterial.end())));

        std::ostringstream req;
        req << "GET " << wsPath << " HTTP/1.1\r\n"
            << "Host: " << hostHdr << "\r\n"
            << "Upgrade: websocket\r\n"
            << "Connection: Upgrade\r\n"
            << "Sec-WebSocket-Key: " << wsKey << "\r\n"
            << "Sec-WebSocket-Version: 13\r\n"
            << "User-Agent: Mozilla/5.0\r\n\r\n";
        const std::string reqStr = req.str();
        Buffer reqBytes(reqStr.begin(), reqStr.end());

        auto reader = std::make_shared<Reader>(source);
        source->write(std::move(reqBytes), [source, reader, expectedAccept, completion = std::move(completion)](Error wErr) mutable {
            if (!wErr.empty()) {
                source->close();
                completion(nullptr, std::move(wErr));
                return;
            }
            reader->until({'\r', '\n', '\r', '\n'}, 16384,
                          [source, reader, expectedAccept, completion = std::move(completion)](Buffer hdrBytes, Error rErr) mutable {
                if (!rErr.empty()) {
                    source->close();
                    completion(nullptr, rErr == "EOF" ? Error("WebSocket handshake closed before HTTP 101") : std::move(rErr));
                    return;
                }
                std::string hdr(hdrBytes.begin(), hdrBytes.end());
                auto lineEnd = hdr.find("\r\n");
                std::string statusLine = lineEnd == std::string::npos ? hdr : hdr.substr(0, lineEnd);
                if (statusLine.find(" 101") == std::string::npos) {
                    source->close();
                    completion(nullptr, "WebSocket upgrade rejected: " + statusLine);
                    return;
                }
                std::string lowerHdr = hdr;
                std::transform(lowerHdr.begin(), lowerHdr.end(), lowerHdr.begin(),
                               [](unsigned char c) { return char(std::tolower(c)); });
                std::string lowerAccept = expectedAccept;
                std::transform(lowerAccept.begin(), lowerAccept.end(), lowerAccept.begin(),
                               [](unsigned char c) { return char(std::tolower(c)); });
                if (lowerHdr.find("sec-websocket-accept:") != std::string::npos &&
                    lowerHdr.find(lowerAccept) == std::string::npos) {
                    source->close();
                    completion(nullptr, "WebSocket Sec-WebSocket-Accept verification failed");
                    return;
                }
                try {
                    Buffer leftover = reader->take();
                    auto ws = std::make_shared<WebSocketClientStream>(source, reader, std::move(leftover));
                    completion(std::move(ws), {});
                } catch (const std::exception &ex) {
                    source->close();
                    completion(nullptr, ex.what());
                }
            });
        });
    } catch (const std::exception &ex) {
        source->close();
        completion(nullptr, ex.what());
    }
}

Buffer uuidBytes(const std::string &text) {
    if (text.size() != 36 || text[8] != '-' || text[13] != '-' || text[18] != '-' || text[23] != '-')
        throw std::runtime_error("Invalid protocol UUID");
    Buffer result;
    result.reserve(16);
    int high = -1;
    for (size_t i = 0; i < text.size(); ++i) {
        if (i == 8 || i == 13 || i == 18 || i == 23) continue;
        char ch = char(std::tolower(static_cast<unsigned char>(text[i])));
        int value = ch >= '0' && ch <= '9' ? ch - '0' : ch >= 'a' && ch <= 'f' ? ch - 'a' + 10 : -1;
        if (value < 0) throw std::runtime_error("Invalid protocol UUID");
        if (high < 0) high = value;
        else { result.push_back(uint8_t(high * 16 + value)); high = -1; }
    }
    if (result.size() != 16) throw std::runtime_error("Invalid protocol UUID");
    return result;
}

void connectBasicProtocol(
    const Node &node,
    const Target &target,
    std::shared_ptr<TransportFactory> factory,
    StreamCallback completion) {
    if (node.type == "vmess") {
        connectVMessProtocol(node, target, std::move(factory), std::move(completion));
        return;
    }
    bool tlsDefault = node.type == "https" || node.type == "socks5-tls" || node.type == "trojan";
    auto tls = tlsOptions(node, tlsDefault);
    if (((node.type == "http" || node.type == "https") || nodeUsesWebSocket(node)) && tls.enabled && tls.alpn.empty())
        tls.alpn = {"http/1.1"};
    factory->tcp(node, tls, [node, target, factory, completion = std::move(completion)](std::shared_ptr<Stream> rawSource, Error error) mutable {
        if (!error.empty() || !rawSource) {
            completion(nullptr, error.empty() ? "Transport did not return a stream" : error);
            return;
        }
        upgradeWebSocketCarrierIfNeeded(node, std::move(rawSource), factory,
            [node, target, factory, completion = std::move(completion)](std::shared_ptr<Stream> source, Error wsErr) mutable {
            if (!wsErr.empty() || !source) {
                completion(nullptr, wsErr.empty() ? "WebSocket carrier failed" : std::move(wsErr));
                return;
            }
            try {
                if (node.type == "direct") {
                    completion(source, {});
                } else if (node.type == "http" || node.type == "https") {
                    connectHttpProxyProtocol(node, target, source, factory, std::move(completion));
                } else if (node.type == "socks5" || node.type == "socks5-tls") {
                    connectSocks5Protocol(node, target, source, factory, std::move(completion));
                } else if (node.type == "vless" || node.type == "trojan") {
                    connectVlessTrojanProtocol(node, target, source, std::move(completion), factory);
                } else {
                    source->close();
                    completion(nullptr, "Unsupported C++ protocol");
                }
            } catch (const std::exception &e) {
                source->close();
                if (completion) completion(nullptr, e.what());
            }
        });
    });
}

namespace {

class StreamDatagrams final : public Datagram, public std::enable_shared_from_this<StreamDatagrams> {
    struct Pending { Buffer data; WriteCallback completion; uint8_t retries = 0; };
    struct Flow {
        Target target;
        std::shared_ptr<Stream> stream;
        std::deque<Pending> pending;
        bool connecting = false, sending = false, established = false;
        uint64_t activity = 0;
    };
    Node node_;
    std::shared_ptr<TransportFactory> factory_;
    std::unordered_map<std::string, std::shared_ptr<Flow>> flows_;
    PacketCallback receive_;
    WriteCallback failure_;
    size_t queued_ = 0, requests_ = 0;
    bool closed_ = false, started_ = false;

    void failFlow(const std::string &key, std::shared_ptr<Flow> flow, Error error) {
        auto found = flows_.find(key);
        if (found == flows_.end() || found->second != flow) return;
        const bool idleBackgroundClose = flow->established && flow->pending.empty() && !flow->sending;
        flows_.erase(found);
        if (flow->stream) flow->stream->close();
        auto pending = std::move(flow->pending);
        flow->pending.clear();
        for (auto &entry : pending) {
            queued_ -= entry.data.size();
            --requests_;
            entry.completion(error);
        }
        if (!closed_ && failure_ && error != "EOF" && !idleBackgroundClose) failure_(error);
    }

    void connectFlow(const std::string &key, std::shared_ptr<Flow> flow) {
        if (closed_ || flow->connecting || flow->stream) return;
        flow->connecting = true;
        auto self = shared_from_this();
        connectProtocol(node_, flow->target, factory_, [self, key, flow](std::shared_ptr<Stream> stream, Error error) {
            if (self->closed_ || !self->flows_.count(key) || self->flows_.at(key) != flow) {
                if (stream) stream->close();
                return;
            }
            flow->connecting = false;
            if (!error.empty() || !stream) {
                self->failFlow(key, flow, error.empty() ? "UDP stream connect failed" : error);
                return;
            }
            flow->stream = std::move(stream);
            self->flush(key, flow);
            self->read(key, flow);
        });
    }

    void flush(const std::string &key, std::shared_ptr<Flow> flow) {
        if (closed_ || !flow->stream || flow->sending || flow->pending.empty()) return;
        flow->sending = true;
        auto self = shared_from_this();
        auto activeStream = flow->stream;
        activeStream->write(flow->pending.front().data, [self, key, flow, activeStream](Error error) {
            if (self->closed_ || !self->flows_.count(key) || self->flows_.at(key) != flow) return;
            flow->sending = false;
            if (!error.empty()) {
                if (flow->established && !flow->pending.empty() && flow->pending.front().retries == 0) {
                    flow->pending.front().retries = 1;
                    if (flow->stream == activeStream) {
                        flow->stream->close();
                        flow->stream.reset();
                    }
                    flow->established = false;
                    self->connectFlow(key, flow);
                    return;
                }
                self->failFlow(key, flow, error);
                return;
            }
            flow->established = true;
            auto entry = std::move(flow->pending.front());
            flow->pending.pop_front();
            self->queued_ -= entry.data.size();
            --self->requests_;
            flow->activity = unixSeconds();
            entry.completion({});
            self->flush(key, flow);
        });
    }

    void read(const std::string &key, std::shared_ptr<Flow> flow) {
        if (closed_ || !started_ || !flow->stream) return;
        auto self = shared_from_this();
        auto activeStream = flow->stream;
        activeStream->read(65535, [self, key, flow, activeStream](Buffer data, bool eof, Error error) {
            if (self->closed_ || !self->flows_.count(key) || self->flows_.at(key) != flow || flow->stream != activeStream) return;
            if (!error.empty()) { self->failFlow(key, flow, error); return; }
            if ((!data.empty() || !eof) && self->receive_) {
                flow->established = true;
                flow->activity = unixSeconds();
                self->receive_(flow->target, std::move(data));
            }
            if (eof) self->failFlow(key, flow, "EOF");
            else self->factory_->post([self, key, flow] { self->read(key, flow); });
        });
    }

    void reap() {
        if (closed_) return;
        auto now = unixSeconds();
        std::vector<std::pair<std::string, std::shared_ptr<Flow>>> stale;
        for (auto &entry : flows_) {
            if (!entry.second->connecting && entry.second->pending.empty() && now - entry.second->activity >= 120)
                stale.push_back(entry);
        }
        for (auto &entry : stale) failFlow(entry.first, entry.second, "EOF");
        if (factory_->after) {
            std::weak_ptr<StreamDatagrams> weak = shared_from_this();
            factory_->after(30, [weak] { if (auto self = weak.lock()) self->reap(); });
        }
    }

public:
    StreamDatagrams(Node node, std::shared_ptr<TransportFactory> factory)
        : node_(std::move(node)), factory_(std::move(factory)) {}

    void send(Target target, Buffer data, WriteCallback completion) override {
        if (closed_) { completion("Datagram session closed"); return; }
        if (data.size() > 65535 || data.size() > maximumQueuedBytes - queued_ || requests_ >= 512) {
            completion("Datagram queue limit exceeded");
            return;
        }
        target.udp = true;
        std::string key = formatHostHeaderAuthority(target.host) + ":" + std::to_string(target.port);
        std::shared_ptr<Flow> flow;
        if (auto found = flows_.find(key); found != flows_.end()) {
            flow = found->second;
        } else {
            if (flows_.size() >= 128) { completion("Datagram flow limit exceeded"); return; }
            flow = std::make_shared<Flow>();
            flow->target = target;
            flow->activity = unixSeconds();
            flows_[key] = flow;
        }
        queued_ += data.size();
        ++requests_;
        flow->pending.push_back({std::move(data), std::move(completion), 0});
        if (flow->stream) { flush(key, flow); return; }
        connectFlow(key, flow);
    }

    void start(PacketCallback receive, WriteCallback failure) override {
        if (started_) { failure("Datagram receiver already started"); return; }
        if (closed_) { failure("Datagram session closed"); return; }
        receive_ = std::move(receive);
        failure_ = std::move(failure);
        started_ = true;
        for (auto &entry : flows_) {
            if (entry.second->stream) read(entry.first, entry.second);
        }
        reap();
    }

    void close() override {
        if (closed_) return;
        closed_ = true;
        auto flows = std::move(flows_);
        flows_.clear();
        for (auto &entry : flows) {
            auto flow = entry.second;
            if (flow->stream) flow->stream->close();
            for (auto &pending : flow->pending) pending.completion("Datagram session closed");
        }
        queued_ = requests_ = 0;
        receive_ = nullptr;
        failure_ = nullptr;
    }
};

} // namespace

void makeBasicDatagram(const Node &node, std::shared_ptr<TransportFactory> factory, DatagramCallback completion) {
    if (node.type == "socks5" || node.type == "socks5-tls") {
        makeSocksDatagram(node, std::move(factory), std::move(completion));
        return;
    }
    completion(std::make_shared<StreamDatagrams>(node, std::move(factory)), {});
}

} // namespace hajimi
