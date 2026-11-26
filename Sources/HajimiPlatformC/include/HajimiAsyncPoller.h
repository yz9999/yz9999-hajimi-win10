#ifndef HAJIMI_ASYNC_POLLER_H
#define HAJIMI_ASYNC_POLLER_H

#ifdef __cplusplus

#include "HajimiPlatformCompat.h"

#include <atomic>
#include <cstdint>
#include <cstring>
#include <unordered_map>
#include <vector>

#if defined(__APPLE__)
#include <sys/event.h>
#include <sys/time.h>
#include <unistd.h>
#elif defined(__linux__)
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <unistd.h>
#endif

namespace hajimi::platform_io {

constexpr short kEventRead  = 0x01;
constexpr short kEventWrite = 0x02;
constexpr short kEventError = 0x04;
constexpr short kEventHangup = 0x08;

struct ReadySocketEvent {
    intptr_t fd{-1};
    uintptr_t token{0};
    short revents{0};
};

/*
 * Cross-Platform Native Event Multiplexer (`HajimiAsyncPoller`)
 *
 * Replaces O(N) per-tick `pollfd` array reconstruction with OS-native incremental
 * kernel event queues:
 * - macOS (`__APPLE__`): Darwin `kqueue()` + `EVFILT_READ` / `EVFILT_WRITE` + `EVFILT_USER`
 *   (zero-pipe kernel wakeup without extra file descriptors or read/write syscalls).
 * - Linux (`__linux__`): `epoll_create1(EPOLL_CLOEXEC)` + `eventfd` wakeup + `EPOLL_CTL_ADD/MOD/DEL`
 *   interest diffing (`O(active_events)` dispatch).
 * - Windows (`_WIN32`): Pre-allocated reusable `WSAPOLLFD` + Winsock loopback wake-pair with
 *   IOCP wakeup helper (`CreateIoCompletionPort` / `PostQueuedCompletionStatus`) for zero-alloc ticks.
 */
class AsyncPoller {
public:
    static constexpr size_t kMaxBatchEvents = 64u;

    AsyncPoller() {
#if defined(__APPLE__)
        kq_ = ::kqueue();
        if (kq_ >= 0) {
            struct kevent kev{};
            EV_SET(&kev, kWakeIdent, EVFILT_USER, EV_ADD | EV_CLEAR, 0, 0, nullptr);
            (void)::kevent(kq_, &kev, 1, nullptr, 0, nullptr);
        }
#elif defined(__linux__)
        epfd_ = ::epoll_create1(EPOLL_CLOEXEC);
        wakeFd_ = ::eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
        if (epfd_ >= 0 && wakeFd_ >= 0) {
            epoll_event ev{};
            ev.events = EPOLLIN;
            ev.data.u64 = kWakeCookie;
            (void)::epoll_ctl(epfd_, EPOLL_CTL_ADD, wakeFd_, &ev);
        }
#elif defined(_WIN32)
        iocp_ = ::CreateIoCompletionPort(INVALID_HANDLE_VALUE, nullptr, 0, 1);
#endif
    }

    ~AsyncPoller() {
#if defined(__APPLE__)
        if (kq_ >= 0) ::close(kq_);
#elif defined(__linux__)
        if (wakeFd_ >= 0) ::close(wakeFd_);
        if (epfd_ >= 0) ::close(epfd_);
#elif defined(_WIN32)
        if (iocp_ != nullptr) ::CloseHandle(iocp_);
#endif
    }

    AsyncPoller(const AsyncPoller &) = delete;
    AsyncPoller &operator=(const AsyncPoller &) = delete;

    bool isValid() const noexcept {
#if defined(__APPLE__)
        return kq_ >= 0;
#elif defined(__linux__)
        return epfd_ >= 0 && wakeFd_ >= 0;
#elif defined(_WIN32)
        return iocp_ != nullptr;
#else
        return true;
#endif
    }

    /* Update or register desired readiness mask (`kEventRead | kEventWrite`). */
    void updateInterest(intptr_t fd, short desiredMask, uintptr_t token) {
        if (fd < 0) return;
        auto it = registered_.find(fd);
        if (desiredMask == 0) {
            if (it != registered_.end()) {
                removeInterest(fd);
            }
            return;
        }
        if (it != registered_.end() && it->second.mask == desiredMask && it->second.token == token) {
            return; // Fast-path: zero kernel syscalls when interest mask is unchanged!
        }

#if defined(__APPLE__)
        if (kq_ >= 0) {
            const short prevMask = (it != registered_.end()) ? it->second.mask : 0;
            struct kevent changes[2];
            int nChanges = 0;
            if ((desiredMask & kEventRead) != (prevMask & kEventRead)) {
                uint16_t flags = (desiredMask & kEventRead) ? (EV_ADD | EV_ENABLE) : EV_DELETE;
                EV_SET(&changes[nChanges++], static_cast<uintptr_t>(fd), EVFILT_READ,
                       flags, 0, 0, reinterpret_cast<void *>(token));
            } else if (desiredMask & kEventRead) {
                EV_SET(&changes[nChanges++], static_cast<uintptr_t>(fd), EVFILT_READ,
                       EV_ADD | EV_ENABLE, 0, 0, reinterpret_cast<void *>(token));
            }
            if ((desiredMask & kEventWrite) != (prevMask & kEventWrite)) {
                uint16_t flags = (desiredMask & kEventWrite) ? (EV_ADD | EV_ENABLE) : EV_DELETE;
                EV_SET(&changes[nChanges++], static_cast<uintptr_t>(fd), EVFILT_WRITE,
                       flags, 0, 0, reinterpret_cast<void *>(token));
            } else if (desiredMask & kEventWrite) {
                EV_SET(&changes[nChanges++], static_cast<uintptr_t>(fd), EVFILT_WRITE,
                       EV_ADD | EV_ENABLE, 0, 0, reinterpret_cast<void *>(token));
            }
            if (nChanges > 0) {
                (void)::kevent(kq_, changes, nChanges, nullptr, 0, nullptr);
            }
        }
#elif defined(__linux__)
        if (epfd_ >= 0) {
            epoll_event ev{};
            if (desiredMask & kEventRead) ev.events |= EPOLLIN | EPOLLRDHUP;
            if (desiredMask & kEventWrite) ev.events |= EPOLLOUT;
            ev.data.fd = static_cast<int>(fd);
            const int op = (it == registered_.end()) ? EPOLL_CTL_ADD : EPOLL_CTL_MOD;
            if (::epoll_ctl(epfd_, op, static_cast<int>(fd), &ev) != 0 && op == EPOLL_CTL_MOD) {
                (void)::epoll_ctl(epfd_, EPOLL_CTL_ADD, static_cast<int>(fd), &ev);
            }
        }
#endif
        registered_[fd] = Entry{desiredMask, token};
    }

    void removeInterest(intptr_t fd) noexcept {
        auto it = registered_.find(fd);
        if (it == registered_.end()) return;
#if defined(__APPLE__)
        if (kq_ >= 0) {
            struct kevent changes[2];
            int nChanges = 0;
            if (it->second.mask & kEventRead) {
                EV_SET(&changes[nChanges++], static_cast<uintptr_t>(fd), EVFILT_READ, EV_DELETE, 0, 0, nullptr);
            }
            if (it->second.mask & kEventWrite) {
                EV_SET(&changes[nChanges++], static_cast<uintptr_t>(fd), EVFILT_WRITE, EV_DELETE, 0, 0, nullptr);
            }
            if (nChanges > 0) {
                (void)::kevent(kq_, changes, nChanges, nullptr, 0, nullptr);
            }
        }
#elif defined(__linux__)
        if (epfd_ >= 0) {
            epoll_event dummy{};
            (void)::epoll_ctl(epfd_, EPOLL_CTL_DEL, static_cast<int>(fd), &dummy);
        }
#endif
        registered_.erase(it);
    }

    /* Thread-safe cross-thread wakeup (coalesced via atomic flag). */
    void wake(intptr_t winWakeSendSock = -1) noexcept {
        if (wakeArmed_.exchange(true, std::memory_order_acq_rel)) {
            return;
        }
#if defined(__APPLE__)
        (void)winWakeSendSock;
        if (kq_ >= 0) {
            struct kevent kev{};
            EV_SET(&kev, kWakeIdent, EVFILT_USER, 0, NOTE_TRIGGER, 0, nullptr);
            (void)::kevent(kq_, &kev, 1, nullptr, 0, nullptr);
        }
#elif defined(__linux__)
        (void)winWakeSendSock;
        if (wakeFd_ >= 0) {
            const uint64_t inc = 1;
            const ssize_t r = ::write(wakeFd_, &inc, sizeof(inc));
            (void)r;
        }
#elif defined(_WIN32)
        if (iocp_ != nullptr) {
            (void)::PostQueuedCompletionStatus(iocp_, 0, kWakeIdent, nullptr);
        }
        if (winWakeSendSock >= 0) {
            const char b = 1;
            (void)::send(static_cast<SOCKET>(winWakeSendSock), &b, 1, 0);
        }
#endif
    }

    /*
     * Waits up to `timeoutMs` and populates up to `maxOut` ready socket events.
     * Returns number of ready socket events (excluding internal wake signal).
     */
    size_t wait(ReadySocketEvent *outEvents,
                size_t maxOut,
                int timeoutMs,
                intptr_t winWakeRecvSock = -1) {
        if (!outEvents || maxOut == 0) return 0;
#if defined(__APPLE__)
        (void)winWakeRecvSock;
        if (kq_ < 0) return 0;
        struct kevent raw[kMaxBatchEvents];
        const int cap = static_cast<int>(maxOut < kMaxBatchEvents ? maxOut : kMaxBatchEvents);
        struct timespec ts{};
        struct timespec *tsPtr = nullptr;
        if (timeoutMs >= 0) {
            ts.tv_sec = timeoutMs / 1000;
            ts.tv_nsec = static_cast<long>(timeoutMs % 1000) * 1000000L;
            tsPtr = &ts;
        }
        int n = ::kevent(kq_, nullptr, 0, raw, cap, tsPtr);
        if (n <= 0) return 0;

        size_t count = 0;
        for (int i = 0; i < n; ++i) {
            if (raw[i].filter == EVFILT_USER && raw[i].ident == kWakeIdent) {
                wakeArmed_.store(false, std::memory_order_release);
                continue;
            }
            const intptr_t fd = static_cast<intptr_t>(raw[i].ident);
            short rev = 0;
            if (raw[i].filter == EVFILT_READ) rev |= kEventRead;
            if (raw[i].filter == EVFILT_WRITE) rev |= kEventWrite;
            if (raw[i].flags & EV_EOF) rev |= kEventHangup;
            if (raw[i].flags & EV_ERROR) rev |= kEventError;

            // Coalesce read + write events for the same fd in the same batch
            bool merged = false;
            for (size_t j = 0; j < count; ++j) {
                if (outEvents[j].fd == fd) {
                    outEvents[j].revents |= rev;
                    merged = true;
                    break;
                }
            }
            if (!merged && count < maxOut) {
                outEvents[count++] = ReadySocketEvent{
                    fd, reinterpret_cast<uintptr_t>(raw[i].udata), rev};
            }
        }
        return count;
#elif defined(__linux__)
        (void)winWakeRecvSock;
        if (epfd_ < 0) return 0;
        epoll_event raw[kMaxBatchEvents];
        const int cap = static_cast<int>(maxOut < kMaxBatchEvents ? maxOut : kMaxBatchEvents);
        int n = ::epoll_wait(epfd_, raw, cap, timeoutMs);
        if (n <= 0) return 0;

        size_t count = 0;
        for (int i = 0; i < n; ++i) {
            if (raw[i].data.u64 == kWakeCookie || raw[i].data.fd == wakeFd_) {
                uint64_t val = 0;
                while (::read(wakeFd_, &val, sizeof(val)) > 0) {}
                wakeArmed_.store(false, std::memory_order_release);
                continue;
            }
            const intptr_t fd = static_cast<intptr_t>(raw[i].data.fd);
            auto it = registered_.find(fd);
            if (it == registered_.end()) continue;
            short rev = 0;
            if (raw[i].events & (EPOLLIN | EPOLLPRI)) rev |= kEventRead;
            if (raw[i].events & EPOLLOUT) rev |= kEventWrite;
            if (raw[i].events & EPOLLERR) rev |= kEventError;
            if (raw[i].events & (EPOLLHUP | EPOLLRDHUP)) rev |= kEventHangup;
            if (count < maxOut) {
                outEvents[count++] = ReadySocketEvent{fd, it->second.token, rev};
            }
        }
        return count;
#elif defined(_WIN32)
        if (registered_.empty()) {
            if (iocp_ != nullptr && timeoutMs > 0) {
                DWORD bytes = 0;
                ULONG_PTR key = 0;
                LPOVERLAPPED ov = nullptr;
                if (::GetQueuedCompletionStatus(iocp_, &bytes, &key, &ov, static_cast<DWORD>(timeoutMs))) {
                    wakeArmed_.store(false, std::memory_order_release);
                }
            } else if (timeoutMs > 0) {
                ::Sleep(static_cast<DWORD>(timeoutMs));
            }
            if (winWakeRecvSock >= 0) {
                char drain[64];
                while (::recv(static_cast<SOCKET>(winWakeRecvSock), drain, sizeof(drain), 0) > 0) {}
                wakeArmed_.store(false, std::memory_order_release);
            }
            return 0;
        }

        winPollBuf_.clear();
        winTokens_.clear();
        winPollBuf_.reserve(registered_.size() + 1u);
        winTokens_.reserve(registered_.size());

        if (winWakeRecvSock >= 0) {
            winPollBuf_.push_back(WSAPOLLFD{static_cast<SOCKET>(winWakeRecvSock), POLLRDNORM, 0});
        }
        for (const auto &kv : registered_) {
            SHORT ev = 0;
            if (kv.second.mask & kEventRead) ev |= POLLRDNORM;
            if (kv.second.mask & kEventWrite) ev |= POLLWRNORM;
            if (ev != 0) {
                winPollBuf_.push_back(WSAPOLLFD{static_cast<SOCKET>(kv.first), ev, 0});
                winTokens_.push_back(kv.second.token);
            }
        }
        if (winPollBuf_.empty()) return 0;

        int rc = ::WSAPoll(winPollBuf_.data(), static_cast<ULONG>(winPollBuf_.size()), timeoutMs);
        if (iocp_ != nullptr) {
            // Drain any queued IOCP wake packets non-blockingly
            DWORD bytes = 0;
            ULONG_PTR key = 0;
            LPOVERLAPPED ov = nullptr;
            while (::GetQueuedCompletionStatus(iocp_, &bytes, &key, &ov, 0)) {}
        }
        if (rc <= 0) return 0;

        size_t offset = 0;
        if (winWakeRecvSock >= 0) {
            if (winPollBuf_[0].revents & (POLLIN | POLLRDNORM | POLLERR | POLLHUP)) {
                char drain[64];
                while (::recv(static_cast<SOCKET>(winWakeRecvSock), drain, sizeof(drain), 0) > 0) {}
                wakeArmed_.store(false, std::memory_order_release);
            }
            offset = 1u;
        }
        size_t count = 0;
        for (size_t i = 0; i < winTokens_.size() && count < maxOut; ++i) {
            SHORT r = winPollBuf_[offset + i].revents;
            if (r == 0) continue;
            short rev = 0;
            if (r & (POLLIN | POLLRDNORM)) rev |= kEventRead;
            if (r & (POLLOUT | POLLWRNORM)) rev |= kEventWrite;
            if (r & POLLERR) rev |= kEventError;
            if (r & POLLHUP) rev |= kEventHangup;
            outEvents[count++] = ReadySocketEvent{
                static_cast<intptr_t>(winPollBuf_[offset + i].fd), winTokens_[i], rev};
        }
        return count;
#else
        return 0;
#endif
    }

    size_t registeredCount() const noexcept { return registered_.size(); }

private:
    struct Entry {
        short mask{0};
        uintptr_t token{0};
    };

    static constexpr uintptr_t kWakeIdent = 0x484A4D57u;
    static constexpr uint64_t kWakeCookie = 0xFFFFFFFF484A4D57ULL;

    std::unordered_map<intptr_t, Entry> registered_;
    std::atomic<bool> wakeArmed_{false};

#if defined(__APPLE__)
    int kq_{-1};
#elif defined(__linux__)
    int epfd_{-1};
    int wakeFd_{-1};
#elif defined(_WIN32)
    HANDLE iocp_{nullptr};
    std::vector<WSAPOLLFD> winPollBuf_;
    std::vector<uintptr_t> winTokens_;
#endif
};

} // namespace hajimi::platform_io

#endif /* __cplusplus */

#endif /* HAJIMI_ASYNC_POLLER_H */
