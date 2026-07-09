#ifndef PQC_CSPRNG_H
#define PQC_CSPRNG_H

#include <stdint.h>
#include <stddef.h>

namespace PQC {
namespace System {

class CSPRNG {
public:
    /**
     * @brief Initialize the HMAC_DRBG CSPRNG.
     * Must be called before generating any random bytes.
     * Seeding is done securely using mbedtls entropy sources.
     */
    static void init();

    /**
     * @brief Generate cryptographically secure random bytes.
     * @param output Buffer to hold the generated random bytes.
     * @param length Number of bytes to generate.
     */
    static void randombytes(uint8_t* output, size_t length);

    /**
     * @brief Safely release the DRBG and entropy contexts.
     */
    static void release();

#ifndef ARDUINO
    /**
     * @brief TEST-ONLY (host build): make randombytes() deterministic.
     *
     * Switches the generator to a reproducible SHA3-512 counter stream seeded
     * from `seed`, so known-answer / regression tests produce identical
     * key material, ciphertexts and signatures on every run. Pass a null seed
     * (or len 0) to restore the OS entropy source. Never compiled into the
     * ESP32 firmware.
     */
    static void set_deterministic(const uint8_t* seed, size_t len);
#endif
};

} // namespace System
} // namespace PQC

#endif // PQC_CSPRNG_H
