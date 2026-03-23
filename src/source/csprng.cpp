#include "../include/csprng.h"
#include <mbedtls/hmac_drbg.h>
#include <mbedtls/entropy.h>
#include <string.h>
#include <stdlib.h>

#ifdef ARDUINO
#include <Arduino.h>
#endif

namespace PQC {
namespace System {

static mbedtls_hmac_drbg_context drbg_ctx;
static mbedtls_entropy_context entropy_ctx;
static bool initialized = false;

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
#ifdef ARDUINO
        while(1) { yield(); }
#else
        abort();
#endif
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
#ifdef ARDUINO
        while(1) { yield(); }
#else
        abort();
#endif
    }
}

void CSPRNG::release() {
    if (initialized) {
        mbedtls_hmac_drbg_free(&drbg_ctx);
        mbedtls_entropy_free(&entropy_ctx);
        initialized = false;
    }
}

} // namespace System
} // namespace PQC
