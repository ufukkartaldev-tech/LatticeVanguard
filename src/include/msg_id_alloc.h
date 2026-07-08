#ifndef PQC_MSG_ID_ALLOC_H
#define PQC_MSG_ID_ALLOC_H

/*
  Shared, platform-neutral message-id reservation.

  The same critical-section body is used by the firmware
  (Messenger::reserve_msg_id, guarded by an ESP32 portMUX spinlock) and by the
  host test suite (where pc_compat.h maps portMUX onto a std::mutex). Keeping
  it in one inline function guarantees the concurrency test exercises the exact
  code path the firmware runs, not a re-implementation.

  The caller supplies the counter and lock, so this stays free of any global
  state and can be unit-tested with a local counter.
*/

#include <stdint.h>

namespace PQC {
namespace Network {

// Atomically increment `counter` under `mux` and return the new value.
// Safe to call concurrently from multiple tasks/threads.
inline uint32_t reserve_msg_id_locked(uint32_t& counter, portMUX_TYPE& mux) {
    portENTER_CRITICAL(&mux);
    uint32_t id = ++counter;
    portEXIT_CRITICAL(&mux);
    return id;
}

} // namespace Network
} // namespace PQC

#endif // PQC_MSG_ID_ALLOC_H
