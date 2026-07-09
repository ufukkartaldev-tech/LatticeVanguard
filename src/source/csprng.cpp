#include "../include/csprng.h"
#include <string.h>
#include <stdlib.h>

#ifdef ARDUINO
#include <Arduino.h>
#include <mbedtls/hmac_drbg.h>
#include <mbedtls/entropy.h>
#else
#include <random>
#include "../include/fips202.h"
#endif

namespace PQC {
namespace System {

static bool initialized = false;

#ifdef ARDUINO

// ---------------------------------------------------------------------------
// Embedded (ESP32) implementation: mbedTLS HMAC_DRBG seeded from the hardware
// entropy pool. This is the production-grade CSPRNG.
// ---------------------------------------------------------------------------

static mbedtls_hmac_drbg_context drbg_ctx;
static mbedtls_entropy_context entropy_ctx;

void CSPRNG::init() {
    if (initialized) return;

    mbedtls_hmac_drbg_init(&drbg_ctx);
    mbedtls_entropy_init(&entropy_ctx);

    const char* custom_pers = "GUMUS_PQC_KEM_SIG_SECURITY_SEED_2026_HMAC_DRBG";

    // Seed the HMAC_DRBG using the entropy pool and SHA-256
    const mbedtls_md_info_t* md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);

    int ret = mbedtls_hmac_drbg_seed(
        &drbg_ctx, md_info,
        mbedtls_entropy_func, &entropy_ctx,
        (const unsigned char *)custom_pers,
        strlen(custom_pers)
    );

    if (ret != 0) {
        // PANIC: Entropi tam atılamadı! Sistemi kilitliyoruz.
        // Güvensiz random sayı üretmektense çalışmaması yeğdir.
        while(1) { yield(); }
    }

    initialized = true;
}

void CSPRNG::randombytes(uint8_t* output, size_t length) {
    if (!initialized) {
        init();
    }

    int ret = mbedtls_hmac_drbg_random(&drbg_ctx, output, length);
    if (ret != 0) {
        // PANIC: DRBG hatası! Sistemi durdur.
        while(1) { yield(); }
    }
}

void CSPRNG::release() {
    if (initialized) {
        mbedtls_hmac_drbg_free(&drbg_ctx);
        mbedtls_entropy_free(&entropy_ctx);
        initialized = false;
    }
}

#else

// ---------------------------------------------------------------------------
// PC simulation fallback (no mbedTLS available). Uses the platform's
// std::random_device, which draws from the OS entropy source (e.g.
// /dev/urandom). Intended for native testing and development only, not for
// production key generation.
// ---------------------------------------------------------------------------

// Test-only deterministic generator state (see set_deterministic).
static bool     det_mode = false;
static uint8_t  det_seed[32];
static uint64_t det_ctr = 0;

void CSPRNG::init() {
    initialized = true;
}

void CSPRNG::set_deterministic(const uint8_t* seed, size_t len) {
    if (seed == nullptr || len == 0) {
        det_mode = false;
        return;
    }
    memset(det_seed, 0, sizeof(det_seed));
    memcpy(det_seed, seed, len < sizeof(det_seed) ? len : sizeof(det_seed));
    det_ctr = 0;
    det_mode = true;
    initialized = true;
}

void CSPRNG::randombytes(uint8_t* output, size_t length) {
    if (!initialized) {
        init();
    }

    if (det_mode) {
        // Reproducible stream: block_i = SHA3-512(seed || counter_le64).
        uint8_t in[40];
        uint8_t block[64];
        memcpy(in, det_seed, 32);
        size_t i = 0;
        while (i < length) {
            for (int b = 0; b < 8; b++) in[32 + b] = (uint8_t)(det_ctr >> (8 * b));
            det_ctr++;
            sha3_512(block, in, sizeof(in));
            size_t chunk = (length - i < sizeof(block)) ? (length - i) : sizeof(block);
            memcpy(output + i, block, chunk);
            i += chunk;
        }
        return;
    }

    std::random_device rd;
    size_t i = 0;
    while (i < length) {
        uint32_t r = rd();
        size_t chunk = (length - i < sizeof(r)) ? (length - i) : sizeof(r);
        memcpy(output + i, &r, chunk);
        i += chunk;
    }
}

void CSPRNG::release() {
    initialized = false;
}

#endif

} // namespace System
} // namespace PQC
