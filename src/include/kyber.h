#ifndef KYBER_H
#define KYBER_H

#include <stdint.h>
#include "params.h"

#include "workspace.h"

using PQC::Memory::CryptoWorkspace;

// Kyber-512 (Level 1) API
int kyber512_keypair(CryptoWorkspace* ws, uint8_t *pk, uint8_t *sk);
int kyber512_encaps(CryptoWorkspace* ws, uint8_t *ct, uint8_t *ss, const uint8_t *pk);
int kyber512_decaps(CryptoWorkspace* ws, uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

// Kyber-768 (Level 2) API
int kyber768_keypair(CryptoWorkspace* ws, uint8_t *pk, uint8_t *sk);
int kyber768_encaps(CryptoWorkspace* ws, uint8_t *ct, uint8_t *ss, const uint8_t *pk);
int kyber768_decaps(CryptoWorkspace* ws, uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

#endif
