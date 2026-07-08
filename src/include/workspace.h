#ifndef PQC_WORKSPACE_H
#define PQC_WORKSPACE_H

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "params.h"
#include "dilithium_params.h"
#include "poly.h"
#include "bitpack.h"

namespace PQC {
namespace Memory {

/**
 * PQC_Workspace (LatticeVanguard Memory Optimization)
 * Core 0 (Ağ) ve Core 1 (Kriptografi) için ayrı bellek alanları.
 * Bellek çakışmalarını ve kitlenmeleri önler.
 */

// Core 1 - Kriptografik Matematik için Çalışma Alanı
// 'data' (anahtarlar) ve 'maths' (hesaplama alanı) artık ayrı adreslerde (struct).
union CryptoWorkspace {
    struct {
        // 1. Yazılım Veri Katmanı (Keys, Ciphertexts) - 12KB
        struct {
            uint8_t pk[3000];
            uint8_t sk[5000];
            uint8_t sig[DILITHIUM2_SIGNBYTES];
            uint8_t ct[1500];
            uint8_t ss[64];
        } data;

        // 2. Matematiksel Ham Katman (Scratchpad)
        // Kyber (KEM) ve Dilithium (DSA) hesaplama alanları asla aynı anda
        // canlı olmadığından, iki scratchpad anonim bir union içinde üst üste
        // bindirilir. Tasarımın hedeflediği "%100 yeniden kullanım" budur ve
        // en büyük statik/heap RAM israfını (Kyber bloğu kadar) ortadan kaldırır.
        struct {
            union {
                struct {
                    polyvec kv1, kv2, kv3, kv4, kv5;
                    poly    kp1, kp2, kp3;
                };
                struct {
                    PQC::DSA::polyvecl dvl, dvl2;
                    PQC::DSA::polyveck dvk1, dvk2, dvk3, dvk4;
                    PQC::DSA::poly dp1, dp2;
                };
            };
        } maths;

        // 3. Matematiksel Sıkıştırılmış Katman (Optimizasyon için opsiyonel)
        struct {
            packed_polyvec pkv1, pkv2;
            PQC::DSA::packed_polyvecl pdvl;
        } compact;
    };
};

// Thread-safe / Task-safe Scoped Memory Allocation (Heap memory exhaustion prevention)
class ScopedWorkspace {
public:
    CryptoWorkspace* ws;
    ScopedWorkspace() {
        ws = new CryptoWorkspace();
        if (ws) {
            memset((void*)ws, 0, sizeof(*ws));
        }
    }
    ~ScopedWorkspace() {
        if (ws) {
            memset((void*)ws, 0, sizeof(*ws)); // Secure wipe (covers the whole union)
            delete ws;
        }
    }
    CryptoWorkspace* operator->() { return ws; }
    operator CryptoWorkspace*() { return ws; }
};

// Core 0 - Ağ verileri için ayrı buffer (Ring Buffer dışında kalanlar)
struct NetworkWorkspace {
    uint8_t temp_buffer[4096];  // Geçici ağ verileri
    uint8_t encryption_buffer[2048];  // Şifreleme için geçici alan
    uint8_t packet_buffer[512];  // Paket oluşturma için
};

extern NetworkWorkspace network_workspace;  // Ağ için global alan kalabilir, PQC için olan silindi

} // namespace Memory
} // namespace PQC

#endif
