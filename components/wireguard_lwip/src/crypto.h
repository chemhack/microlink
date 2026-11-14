#ifndef _CRYPTO_H_
#define _CRYPTO_H_

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include "sdkconfig.h"

// ESP32-P4 chip revision v3.x added the bit-manipulation extension (Zb), per
// Espressif's "ESP32-P4 Chip Revision v3.x User Guide", but ESP-IDF's -march
// leaves it out (espressif/esp-idf#19299). Images for v3.x chips carry an
// assembly ChaCha20 that rotates with Zbb (crypto/refc/chacha20_esp32p4.S,
// built by CMakeLists.txt on the same terms) next to the C one, and use it
// when crypto_esp32p4_zb is set: at startup, on revision v3.2 or later, the
// revision it has been verified on.
#if defined(CONFIG_IDF_TARGET_ESP32P4) && !defined(CONFIG_ESP32P4_SELECTS_REV_LESS_V3) && \
	defined(__GNUC__) && !defined(__clang__)
#define CRYPTO_ESP32P4_ZB 1
extern bool crypto_esp32p4_zb;
#endif

// On the ESP32-P4 a 64-bit product takes a mul and a mulhu, so Poly1305 keeps
// its accumulator in base 2^32, which needs fewer of them than base 2^26
// (crypto/refc/poly1305-base32.h).
#if defined(CONFIG_IDF_TARGET_ESP32P4)
#define POLY1305_BASE32 1
#endif

// BLAKE2S IMPLEMENTATION
#include "crypto/refc/blake2s.h"
#define wireguard_blake2s_ctx blake2s_ctx
#define wireguard_blake2s_init(ctx,outlen,key,keylen) blake2s_init(ctx,outlen,key,keylen)
#define wireguard_blake2s_update(ctx,in,inlen) blake2s_update(ctx,in,inlen)
#define wireguard_blake2s_final(ctx,out) blake2s_final(ctx,out)
#define wireguard_blake2s(out,outlen,key,keylen,in,inlen) blake2s(out,outlen,key,keylen,in,inlen)

// X25519 IMPLEMENTATION
#include "crypto/refc/x25519.h"
#define wireguard_x25519(a,b,c)	x25519(a,b,c,1)

//#include "crypto/cortex/scalarmult.h"
//#define wireguard_x25519(a,b,c)	crypto_scalarmult_curve25519(a,b,c)

// CHACHA20POLY1305 IMPLEMENTATION
#include "crypto/refc/chacha20poly1305.h"
#define wireguard_aead_encrypt(dst,src,srclen,ad,adlen,nonce,key) chacha20poly1305_encrypt(dst,src,srclen,ad,adlen,nonce,key)
#define wireguard_aead_decrypt(dst,src,srclen,ad,adlen,nonce,key) chacha20poly1305_decrypt(dst,src,srclen,ad,adlen,nonce,key)
#define wireguard_xaead_encrypt(dst,src,srclen,ad,adlen,nonce,key) xchacha20poly1305_encrypt(dst,src,srclen,ad,adlen,nonce,key)
#define wireguard_xaead_decrypt(dst,src,srclen,ad,adlen,nonce,key) xchacha20poly1305_decrypt(dst,src,srclen,ad,adlen,nonce,key)


// Endian / unaligned helper macros
#define U8C(v) (v##U)
#define U32C(v) (v##U)

#define U8V(v) ((uint8_t)(v) & U8C(0xFF))
#define U32V(v) ((uint32_t)(v) & U32C(0xFFFFFFFF))

#define U8TO32_LITTLE(p) \
  (((uint32_t)((p)[0])      ) | \
   ((uint32_t)((p)[1]) <<  8) | \
   ((uint32_t)((p)[2]) << 16) | \
   ((uint32_t)((p)[3]) << 24))

#define U8TO64_LITTLE(p) \
  (((uint64_t)((p)[0])      ) | \
   ((uint64_t)((p)[1]) <<  8) | \
   ((uint64_t)((p)[2]) << 16) | \
   ((uint64_t)((p)[3]) << 24) | \
   ((uint64_t)((p)[4]) << 32) | \
   ((uint64_t)((p)[5]) << 40) | \
   ((uint64_t)((p)[6]) << 48) | \
   ((uint64_t)((p)[7]) << 56))

#define U16TO8_BIG(p, v) \
  do { \
    (p)[1] = U8V((v)      ); \
    (p)[0] = U8V((v) >>  8); \
  } while (0)

#define U32TO8_LITTLE(p, v) \
  do { \
    (p)[0] = U8V((v)      ); \
    (p)[1] = U8V((v) >>  8); \
    (p)[2] = U8V((v) >> 16); \
    (p)[3] = U8V((v) >> 24); \
  } while (0)

#define U32TO8_BIG(p, v) \
  do { \
    (p)[3] = U8V((v)      ); \
    (p)[2] = U8V((v) >>  8); \
    (p)[1] = U8V((v) >> 16); \
    (p)[0] = U8V((v) >> 24); \
  } while (0)

#define U64TO8_LITTLE(p, v) \
  do { \
    (p)[0] = U8V((v)      ); \
    (p)[1] = U8V((v) >>  8); \
    (p)[2] = U8V((v) >> 16); \
    (p)[3] = U8V((v) >> 24); \
    (p)[4] = U8V((v) >> 32); \
    (p)[5] = U8V((v) >> 40); \
    (p)[6] = U8V((v) >> 48); \
    (p)[7] = U8V((v) >> 56); \
} while (0)

#define U64TO8_BIG(p, v) \
  do { \
    (p)[7] = U8V((v)      ); \
    (p)[6] = U8V((v) >>  8); \
    (p)[5] = U8V((v) >> 16); \
    (p)[4] = U8V((v) >> 24); \
    (p)[3] = U8V((v) >> 32); \
    (p)[2] = U8V((v) >> 40); \
    (p)[1] = U8V((v) >> 48); \
    (p)[0] = U8V((v) >> 56); \
} while (0)


void crypto_zero(void *dest, size_t len);
bool crypto_equal(const void *a, const void *b, size_t size);

#endif /* _CRYPTO_H_ */

