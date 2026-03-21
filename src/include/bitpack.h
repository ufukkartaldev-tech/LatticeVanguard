#ifndef PQC_BITPACK_H
#define PQC_BITPACK_H

#include <stdint.h>
#include "params.h"
#include "dilithium_params.h"

namespace PQC {
namespace Utils {

/**
 * BitPacker (LatticeVanguard Data Compression)
 * Verileri ham halleriyle (32-bit/16-bit) tutmak yerine, 
 * bit seviyesinde paketleyerek RAM'den %25-40 kar eder.
 */
class BitPacker {
public:
    // Kyber: 2 tane 12-bit katsayıyı 3 byte (24-bit) içine paketle
    static void pack_kyber_poly(uint8_t* out, const int16_t* in) {
        for (int i = 0; i < 128; i++) {
            uint16_t t0 = (uint16_t)in[2 * i] & 0x0FFF;
            uint16_t t1 = (uint16_t)in[2 * i + 1] & 0x0FFF;
            out[3 * i + 0] = (uint8_t)(t0 & 0xFF);
            out[3 * i + 1] = (uint8_t)((t0 >> 8) | ((t1 & 0x0F) << 4));
            out[3 * i + 2] = (uint8_t)(t1 >> 4);
        }
    }

    static void unpack_kyber_poly(int16_t* out, const uint8_t* in) {
        for (int i = 0; i < 128; i++) {
            out[2 * i] = (int16_t)(in[3 * i + 0] | ((uint16_t)(in[3 * i + 1] & 0x0F) << 8));
            out[2 * i + 1] = (int16_t)((in[3 * i + 1] >> 4) | ((uint16_t)in[3 * i + 2] << 4));
        }
    }

    // Dilithium: 4 tane 23-bit katsayıyı 12 byte (96-bit) içine paketle
    // (Her katsayı 32-bit yerine 24-bit (3 byte) yer kaplasın -> %25 tasarruf)
    static void pack_dilithium_poly(uint8_t* out, const int32_t* in) {
        for (int i = 0; i < 256; i++) {
            uint32_t t = (uint32_t)in[i] & 0x007FFFFF; // 23-bit mask
            out[3 * i + 0] = (uint8_t)(t & 0xFF);
            out[3 * i + 1] = (uint8_t)((t >> 8) & 0xFF);
            out[3 * i + 2] = (uint8_t)((t >> 16) & 0xFF);
        }
    }

    static void unpack_dilithium_poly(int32_t* out, const uint8_t* in) {
        for (int i = 0; i < 256; i++) {
            uint32_t t = ((uint32_t)in[3 * i + 0]) |
                         ((uint32_t)in[3 * i + 1] << 8) |
                         ((uint32_t)in[3 * i + 2] << 16);
            
            // Constant-Time Sign Extension (23-bit to 32-bit)
            // Dallanma (branching) yok, sadece bit seviyesinde işlem.
            uint32_t sign_bit = (t >> 22) & 0x01;
            uint32_t mask = (uint32_t)(-(int32_t)sign_bit); 
            t |= (mask & 0xFF800000);
            
            out[i] = (int32_t)t;
        }
    }
};

} // namespace Utils
} // namespace PQC

#endif
