#include "test_suite.h"
#include "../include/pqc_config.h"

#ifdef ENABLE_PQC_TESTS
#include "../include/dilithium.h"
#include <string.h>

#include "../include/workspace.h"

namespace PQC {
namespace Test {

using Memory::ScopedWorkspace;

bool ForgeTester::test_dilithium_malleability() {
    uint8_t d_pk[2048], d_sk[4096], sig[2420]; 
    size_t siglen;
    const uint8_t msg[] = "Test Message";
    
    ScopedWorkspace local_ws;
    if (!local_ws.ws) { Serial.println("OOM!"); return; }
    
    DSA::Dilithium2::keypair(local_ws, d_pk, d_sk);
    DSA::Dilithium2::sign(local_ws, sig, &siglen, msg, sizeof(msg), d_sk);
    
    // Bozma hamlesi
    sig[50] ^= 0xFF;
    
    int res = DSA::Dilithium2::verify(local_ws, sig, siglen, msg, sizeof(msg), d_pk);
    return (res != 0); // Hata dönmeli
}

} // namespace Test
} // namespace PQC
#endif
