#ifndef KYBER_MODULAR_H
#define KYBER_MODULAR_H

#include <stdint.h>
#include <stddef.h>
#include "params.h"
#include "workspace.h"

namespace PQC {
namespace KEM {

using Memory::CryptoWorkspace;

class KyberBase {
protected:
    // RAM tasarrufu için matrisi tek seferde değil, satır satır üretiyoruz.
    static void gen_matrix_row(polyvec *a_row, const uint8_t seed[32], int row_idx, int k, int transposed);
};

class Kyber512 : public KyberBase {
public:
    static const int K = 2;
    static int keypair(CryptoWorkspace* ws, uint8_t *pk, uint8_t *sk);
    static int encaps(CryptoWorkspace* ws, uint8_t *ct, uint8_t *ss, const uint8_t *pk);
    static int decaps(CryptoWorkspace* ws, uint8_t *ss, const uint8_t *ct, const uint8_t *sk);
private:
    static void indcpa_enc(CryptoWorkspace* ws, uint8_t *ct, const uint8_t *msg, const uint8_t *pk, const uint8_t *coins);
};

class Kyber768 : public KyberBase {
public:
    static const int K = 3;
    static int keypair(CryptoWorkspace* ws, uint8_t *pk, uint8_t *sk);
    static int encaps(CryptoWorkspace* ws, uint8_t *ct, uint8_t *ss, const uint8_t *pk);
    static int decaps(CryptoWorkspace* ws, uint8_t *ss, const uint8_t *ct, const uint8_t *sk);
private:
    static void indcpa_enc(CryptoWorkspace* ws, uint8_t *ct, const uint8_t *msg, const uint8_t *pk, const uint8_t *coins);
};

} // namespace KEM
} // namespace PQC

#endif
