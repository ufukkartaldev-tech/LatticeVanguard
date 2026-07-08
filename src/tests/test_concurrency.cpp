#include "test_suite.h"

// Host-only concurrency test. Exercises the exact message-id reservation code
// path the firmware uses (reserve_msg_id_locked), but drives it from several
// std::threads so the "no lost updates / no duplicate ids" guarantee can be
// validated on a PC without ESP32 hardware.
#ifndef ARDUINO

#include "../include/pc_compat.h"     // provides the portMUX shim
#include "../include/msg_id_alloc.h"  // the shared reservation helper

#include <thread>
#include <vector>
#include <atomic>

namespace PQC {
namespace Test {

bool ConcurrencyTester::test_msg_id_allocation() {
    constexpr int kThreads     = 8;
    constexpr int kPerThread   = 5000;
    constexpr int kTotal       = kThreads * kPerThread;

    uint32_t counter = 1000;                 // mirrors firmware's initial value
    portMUX_TYPE mux = portMUX_INITIALIZER_UNLOCKED;

    std::vector<uint32_t> ids(kTotal, 0);
    std::atomic<int> slot{0};

    auto worker = [&]() {
        for (int i = 0; i < kPerThread; i++) {
            uint32_t id = PQC::Network::reserve_msg_id_locked(counter, mux);
            ids[slot.fetch_add(1, std::memory_order_relaxed)] = id;
        }
    };

    std::vector<std::thread> pool;
    pool.reserve(kThreads);
    for (int t = 0; t < kThreads; t++) pool.emplace_back(worker);
    for (auto& th : pool) th.join();

    // No lost updates: the counter advanced by exactly kTotal.
    if (counter != 1000u + kTotal) return false;
    if (slot.load() != kTotal) return false;

    // No duplicates and full coverage of the contiguous range (1001..1000+kTotal).
    std::vector<uint8_t> seen(kTotal + 1, 0);
    for (uint32_t id : ids) {
        uint32_t off = id - 1000u;           // expected 1..kTotal
        if (off < 1 || off > (uint32_t)kTotal) return false;
        if (seen[off]) return false;         // duplicate id handed out
        seen[off] = 1;
    }
    return true;
}

} // namespace Test
} // namespace PQC

#endif // !ARDUINO
