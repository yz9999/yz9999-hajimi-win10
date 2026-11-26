#pragma once
#include "Runtime.hpp"
#include "PlatformCompat.hpp"
#include <algorithm>
#include <cctype>
#include <deque>
#include <mutex>
#include <utility>
#include <vector>

namespace hajimi {
/// Serial, bounded, thread-safe writes for framed streams with high/low-water flow control
/// and automatic 32 KiB write coalescing across queued non-FIN chunks.
class OrderedWriter : public std::enable_shared_from_this<OrderedWriter> {
    static constexpr size_t kMaxCoalescedWriteBytes = 32768;
    struct Entry { Buffer data; size_t bytes; WriteCallback completion; bool fin; };
    mutable std::mutex mu_;
    std::shared_ptr<Stream> source_;
    std::deque<Entry> entries_;
    std::vector<std::function<void()>> drainWaiters_;
    size_t bytes_ = 0;
    size_t maxBytes_ = maximumQueuedBytes;
    size_t maxEntries_ = 128;
    size_t coalesceMaxBytes_ = 0;
    bool active_ = false, closed_ = false, finishing_ = false;
    uint64_t generation_ = 0;

    std::vector<std::function<void()>> takeDrainWaitersLocked() {
        if (closed_ || finishing_ || bytes_ > maxBytes_ / 2 || entries_.size() >= maxEntries_ / 2 || drainWaiters_.empty()) {
            return {};
        }
        auto waiters = std::move(drainWaiters_);
        drainWaiters_.clear();
        return waiters;
    }

    static void invokeWaiters(std::vector<std::function<void()>> &waiters) {
        for (auto &w : waiters) if (w) w();
    }

    void flush() {
        std::shared_ptr<Stream> src;
        uint64_t generation = 0;
        bool isFin = false;
        size_t batchCount = 0;
        size_t batchBytes = 0;
        Buffer payload;
        {
            std::lock_guard<std::mutex> lk(mu_);
            if (closed_ || active_ || entries_.empty()) return;
            active_ = true;
            generation = generation_;
            src = source_;
            if (entries_.front().fin) {
                isFin = true;
            } else {
                batchCount = 1;
                batchBytes = entries_.front().bytes;
                while (coalesceMaxBytes_ > 0 &&
                       batchCount < entries_.size() &&
                       !entries_[batchCount].fin &&
                       batchBytes + entries_[batchCount].bytes <= coalesceMaxBytes_) {
                    batchBytes += entries_[batchCount].bytes;
                    ++batchCount;
                }
                if (batchCount == 1) {
                    payload = std::move(entries_.front().data);
                } else {
                    payload.reserve(batchBytes);
                    for (size_t i = 0; i < batchCount; ++i) {
                        payload.insert(payload.end(), entries_[i].data.begin(), entries_[i].data.end());
                        Buffer().swap(entries_[i].data);
                    }
                }
            }
        }

        auto self = shared_from_this();
        if (isFin) {
            src->shutdownWrite([self, generation](Error error) {
                WriteCallback entryCb;
                std::deque<Entry> remaining;
                std::vector<std::function<void()>> waiters;
                std::shared_ptr<Stream> toClose;
                bool shouldFlushNext = false;
                {
                    std::lock_guard<std::mutex> lk(self->mu_);
                    if (generation != self->generation_ || self->closed_) return;
                    self->active_ = false;
                    if (!self->entries_.empty()) {
                        auto entry = std::move(self->entries_.front());
                        self->entries_.pop_front();
                        self->bytes_ = self->bytes_ >= entry.bytes ? self->bytes_ - entry.bytes : 0;
                        entryCb = std::move(entry.completion);
                    }
                    if (!error.empty()) {
                        self->closed_ = true;
                        toClose = self->source_;
                        remaining = std::move(self->entries_);
                        self->entries_.clear();
                        self->bytes_ = 0;
                        self->drainWaiters_.clear();
                    } else {
                        waiters = self->takeDrainWaitersLocked();
                        shouldFlushNext = !self->entries_.empty();
                    }
                }
                if (toClose) toClose->close();
                if (entryCb) entryCb(error);
                for (auto &pending : remaining) if (pending.completion) pending.completion(error);
                invokeWaiters(waiters);
                if (shouldFlushNext) self->flush();
            });
            return;
        }

        src->write(std::move(payload), [self, generation, batchCount, batchBytes](Error error) {
            std::vector<WriteCallback> done;
            std::deque<Entry> remaining;
            std::vector<std::function<void()>> waiters;
            std::shared_ptr<Stream> toClose;
            bool shouldFlushNext = false;
            {
                std::lock_guard<std::mutex> lk(self->mu_);
                if (generation != self->generation_ || self->closed_) return;
                self->active_ = false;
                done.reserve(batchCount);
                const size_t popCount = std::min(batchCount, self->entries_.size());
                for (size_t i = 0; i < popCount; ++i) {
                    done.push_back(std::move(self->entries_.front().completion));
                    self->entries_.pop_front();
                }
                self->bytes_ = self->bytes_ >= batchBytes ? self->bytes_ - batchBytes : 0;
                if (!error.empty()) {
                    self->closed_ = true;
                    toClose = self->source_;
                    remaining = std::move(self->entries_);
                    self->entries_.clear();
                    self->bytes_ = 0;
                    self->drainWaiters_.clear();
                } else {
                    waiters = self->takeDrainWaitersLocked();
                    shouldFlushNext = !self->entries_.empty();
                }
            }
            if (toClose) toClose->close();
            if (!error.empty()) {
                for (auto &cb : done) if (cb) cb(error);
                for (auto &pending : remaining) if (pending.completion) pending.completion(error);
            } else {
                for (auto &cb : done) if (cb) cb({});
                invokeWaiters(waiters);
                if (shouldFlushNext) self->flush();
            }
        });
    }
public:
    explicit OrderedWriter(std::shared_ptr<Stream> source, size_t maxBytes = maximumQueuedBytes,
                           size_t maxEntries = 128, size_t coalesceMaxBytes = 0)
        : source_(std::move(source)), maxBytes_(maxBytes), maxEntries_(maxEntries),
          coalesceMaxBytes_(coalesceMaxBytes) {}
    void write(Buffer data, WriteCallback completion) {
        {
            std::lock_guard<std::mutex> lk(mu_);
            if (closed_ || finishing_) {
                if (completion) completion("Stream write side closed");
                return;
            }
            const size_t sz = data.size();
            if (entries_.size() >= maxEntries_ || sz > maxBytes_ - bytes_) {
                if (completion) completion("Protocol write queue limit exceeded");
                return;
            }
            bytes_ += sz;
            entries_.push_back({std::move(data), sz, std::move(completion), false});
        }
        flush();
    }
    void finish(WriteCallback completion) {
        {
            std::lock_guard<std::mutex> lk(mu_);
            if (closed_ || finishing_) {
                if (completion) completion("Stream write side closed");
                return;
            }
            if (!source_->supportsHalfClose()) {
                if (completion) completion("Protocol carrier does not support half-close");
                return;
            }
            if (entries_.size() >= maxEntries_) {
                if (completion) completion("Protocol write queue limit exceeded");
                return;
            }
            finishing_ = true;
            entries_.push_back({{}, 0, std::move(completion), true});
        }
        flush();
    }
    void close() {
        std::deque<Entry> remaining;
        {
            std::lock_guard<std::mutex> lk(mu_);
            if (closed_) return;
            closed_ = true;
            ++generation_;
            active_ = false;
            bytes_ = 0;
            remaining = std::move(entries_);
            entries_.clear();
            drainWaiters_.clear();
        }
        for (auto &pending : remaining) {
            if (pending.completion) pending.completion("Stream closed");
        }
    }
    size_t available() const {
        std::lock_guard<std::mutex> lk(mu_);
        return closed_ || finishing_ || entries_.size() >= maxEntries_ ? 0 : maxBytes_ - bytes_;
    }
    bool canAccept(size_t bytes) const {
        std::lock_guard<std::mutex> lk(mu_);
        return !closed_ && !finishing_ && entries_.size() < maxEntries_ && bytes <= maxBytes_ - bytes_;
    }
    void onDrain(std::function<void()> callback) {
        bool invokeNow = false;
        {
            std::lock_guard<std::mutex> lk(mu_);
            if (!closed_ && !finishing_ && entries_.size() < maxEntries_ && bytes_ <= maxBytes_ / 2) {
                invokeNow = true;
            } else if (!closed_ && !finishing_ && drainWaiters_.size() < 64) {
                drainWaiters_.push_back(std::move(callback));
                return;
            } else {
                return;
            }
        }
        if (invokeNow && callback) callback();
    }
};

class BufferedStream final : public Stream {
    std::shared_ptr<Stream> source_;
    std::shared_ptr<Reader> reader_;
    std::shared_ptr<OrderedWriter> writer_;
public:
    BufferedStream(std::shared_ptr<Stream> source, std::shared_ptr<Reader> reader)
        : source_(std::move(source)), reader_(std::move(reader)), writer_(std::make_shared<OrderedWriter>(source_, maximumQueuedBytes, 128, 32768)) {}
    void write(Buffer data, WriteCallback completion) override { writer_->write(std::move(data), std::move(completion)); }
    void read(size_t maximum, ReadCallback completion) override { reader_->some(maximum, std::move(completion)); }
    void close() override { writer_->close(); reader_->close(); }
    void shutdownWrite(WriteCallback completion) override { writer_->finish(std::move(completion)); }
    bool supportsHalfClose() const override { return source_->supportsHalfClose(); }
};

inline void append16(Buffer &data, uint16_t value) { data.push_back(uint8_t(value >> 8)); data.push_back(uint8_t(value)); }
inline void append32(Buffer &data, uint32_t value) { for (int n=24; n>=0; n-=8) data.push_back(uint8_t(value >> n)); }
inline void append64(Buffer &data, uint64_t value) { for (int n=56; n>=0; n-=8) data.push_back(uint8_t(value >> n)); }
inline uint16_t read16(const Buffer &data, size_t offset=0) { return uint16_t(data.at(offset)) << 8 | data.at(offset+1); }
inline Buffer bytes(const std::string &value) { return Buffer(value.begin(), value.end()); }
inline Buffer prefix(Buffer value, size_t length) { value.resize(std::min(value.size(), length)); return value; }
inline bool muxTarget(const Target &target) { return target.host == "v1.mux.cool" && target.port == 9527; }

inline std::string unbracketAndStripZone(std::string host) {
    if (host.size() >= 2 && host.front() == '[' && host.back() == ']')
        host = host.substr(1, host.size() - 2);
    if (host.find(':') != std::string::npos) {
        auto scope = host.find('%');
        if (scope != std::string::npos) host.resize(scope);
    }
    return host;
}

inline std::string formatHostHeaderAuthority(const std::string &rawHost) {
    if (rawHost.find(':') != std::string::npos) {
        return "[" + unbracketAndStripZone(rawHost) + "]";
    }
    return rawHost;
}

} // namespace hajimi
