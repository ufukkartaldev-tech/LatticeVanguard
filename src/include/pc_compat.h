#ifndef PQC_PC_COMPAT_H
#define PQC_PC_COMPAT_H

/*
  PC COMPATIBILITY LAYER
  ----------------------
  Provides host-side (non-Arduino) replacements for the small subset of the
  Arduino runtime that the firmware relies on (Serial, millis, delay, ...),
  so the PC test/simulation build can compile and run under g++/MSVC.

  On real hardware (ARDUINO defined) this header is inert and the genuine
  Arduino APIs are used instead.
*/

#ifndef ARDUINO

#include <cstdint>
#include <cstdio>
#include <chrono>
#include <thread>
#include <mutex>

// ESP32 critical-section (portMUX) shim for the host build. On real hardware
// these come from FreeRTOS; here a std::mutex provides the same mutual
// exclusion so shared code (e.g. reserve_msg_id_locked) can be unit-tested.
struct portMUX_TYPE { std::mutex mtx; };
#define portMUX_INITIALIZER_UNLOCKED {}
inline void portENTER_CRITICAL(portMUX_TYPE* m) { m->mtx.lock(); }
inline void portEXIT_CRITICAL(portMUX_TYPE* m) { m->mtx.unlock(); }

// Monotonic millisecond/microsecond counters (Arduino millis()/micros()).
inline uint32_t millis() {
    using namespace std::chrono;
    static const steady_clock::time_point start = steady_clock::now();
    return static_cast<uint32_t>(
        duration_cast<milliseconds>(steady_clock::now() - start).count());
}

inline uint32_t micros() {
    using namespace std::chrono;
    static const steady_clock::time_point start = steady_clock::now();
    return static_cast<uint32_t>(
        duration_cast<microseconds>(steady_clock::now() - start).count());
}

inline void delay(uint32_t ms) {
    std::this_thread::sleep_for(std::chrono::milliseconds(ms));
}

inline void yield() {}

// Minimal Serial replacement that mirrors output to stdout.
class PCSerialStub {
public:
    void begin(unsigned long) {}
    int available() { return 0; }
    int read() { return -1; }

    void print(const char* s) { std::fputs(s, stdout); }
    void print(char c) { std::fputc(c, stdout); }
    void print(int v) { std::printf("%d", v); }
    void print(unsigned int v) { std::printf("%u", v); }
    void print(long v) { std::printf("%ld", v); }
    void print(unsigned long v) { std::printf("%lu", v); }
    void print(double v) { std::printf("%f", v); }

    void println() { std::fputc('\n', stdout); }
    void println(const char* s) { std::printf("%s\n", s); }
    void println(char c) { std::printf("%c\n", c); }
    void println(int v) { std::printf("%d\n", v); }
    void println(unsigned int v) { std::printf("%u\n", v); }
    void println(long v) { std::printf("%ld\n", v); }
    void println(unsigned long v) { std::printf("%lu\n", v); }
    void println(double v) { std::printf("%f\n", v); }

    template <typename... Args>
    void printf(const char* fmt, Args... args) { std::printf(fmt, args...); }
};

inline PCSerialStub Serial;

#endif // ARDUINO
#endif // PQC_PC_COMPAT_H
