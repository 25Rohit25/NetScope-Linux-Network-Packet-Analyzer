#pragma once

#include <condition_variable>
#include <cstddef>
#include <mutex>
#include <queue>
#include <stdexcept>
#include <utility>

namespace netscope {

template <typename T>
class ConcurrentQueue {
public:
    explicit ConcurrentQueue(std::size_t capacity) : capacity_(capacity) {
        if (capacity == 0) throw std::invalid_argument("queue capacity must be positive");
    }

    ConcurrentQueue(const ConcurrentQueue&) = delete;
    ConcurrentQueue& operator=(const ConcurrentQueue&) = delete;

    // Capture must never wait for a worker: a full queue drops the new packet.
    bool try_push(T item, std::size_t* resulting_depth = nullptr) {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (closed_ || items_.size() == capacity_) {
                if (resulting_depth) *resulting_depth = items_.size();
                return false;
            }
            items_.push(std::move(item));
            if (resulting_depth) *resulting_depth = items_.size();
        }
        ready_.notify_one();
        return true;
    }

    // Returns false only after close and after all queued packets have drained.
    bool pop(T& item) {
        std::unique_lock<std::mutex> lock(mutex_);
        ready_.wait(lock, [this] { return closed_ || !items_.empty(); });
        if (items_.empty()) return false;
        item = std::move(items_.front());
        items_.pop();
        return true;
    }

    void close() {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            closed_ = true;
        }
        ready_.notify_all();
    }

    std::size_t size() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return items_.size();
    }

private:
    const std::size_t capacity_;
    mutable std::mutex mutex_;
    std::condition_variable ready_;
    std::queue<T> items_;
    bool closed_ = false;
};

}  // namespace netscope
