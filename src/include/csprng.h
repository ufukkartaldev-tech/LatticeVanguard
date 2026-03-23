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
};

} // namespace System
} // namespace PQC

#endif // PQC_CSPRNG_H
