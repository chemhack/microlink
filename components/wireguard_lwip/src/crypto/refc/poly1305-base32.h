/*
	Poly1305 with the accumulator in base 2^32: four 32-bit words and a top
	word of a few bits. OpenSSL's 32-bit code uses the same representation.

	Clamping clears the low two bits of r words 1-3, so a product term that
	lands at 2^128 or above folds back as s_i = r_i + (r_i >> 2) = 5 * r_i / 4,
	since 2^130 = 5 mod p. Each column of h * r is then four 32x32 products,
	each below 2^61, plus a small one, and fits in 64 bits. A block costs 16
	wide products instead of the 25 of the base 2^26 code in
	poly1305-donna-32.h, which matters where a 64-bit product takes both a mul
	and a mulhu. The interface is that of poly1305-donna-32.h, and
	poly1305-donna.c includes one or the other.
*/

#include <stdint.h>
#include <string.h>

#define poly1305_block_size 16

typedef struct poly1305_state_internal_t {
	uint32_t r[4];
	uint32_t s[4];		/* s[i] = r[i] + (r[i] >> 2) for i = 1..3; s[0] unused */
	uint32_t h[5];
	uint32_t pad[4];
	size_t leftover;
	unsigned char buffer[poly1305_block_size];
	unsigned char final;
} poly1305_state_internal_t;

_Static_assert(sizeof(poly1305_state_internal_t) <= sizeof(((poly1305_context *)0)->opaque),
	"poly1305 state does not fit in poly1305_context");

static inline uint32_t
poly1305_load32(const unsigned char *p) {
	uint32_t v;
	memcpy(&v, p, 4);	/* little-endian target */
	return v;
}

static inline void
poly1305_store32(unsigned char *p, uint32_t v) {
	memcpy(p, &v, 4);
}

void
poly1305_init(poly1305_context *ctx, const unsigned char key[32]) {
	poly1305_state_internal_t *st = (poly1305_state_internal_t *)ctx;

	/* r &= 0x0ffffffc0ffffffc0ffffffc0fffffff */
	st->r[0] = poly1305_load32(&key[0]) & 0x0fffffff;
	st->r[1] = poly1305_load32(&key[4]) & 0x0ffffffc;
	st->r[2] = poly1305_load32(&key[8]) & 0x0ffffffc;
	st->r[3] = poly1305_load32(&key[12]) & 0x0ffffffc;
	st->s[0] = 0;
	st->s[1] = st->r[1] + (st->r[1] >> 2);
	st->s[2] = st->r[2] + (st->r[2] >> 2);
	st->s[3] = st->r[3] + (st->r[3] >> 2);

	st->h[0] = st->h[1] = st->h[2] = st->h[3] = st->h[4] = 0;

	st->pad[0] = poly1305_load32(&key[16]);
	st->pad[1] = poly1305_load32(&key[20]);
	st->pad[2] = poly1305_load32(&key[24]);
	st->pad[3] = poly1305_load32(&key[28]);

	st->leftover = 0;
	st->final = 0;
}

static void
poly1305_blocks(poly1305_state_internal_t *st, const unsigned char *m, size_t bytes) {
	const uint32_t padbit = st->final ? 0 : 1;	/* 2^128 */
	const uint32_t r0 = st->r[0], r1 = st->r[1], r2 = st->r[2], r3 = st->r[3];
	const uint32_t s1 = st->s[1], s2 = st->s[2], s3 = st->s[3];
	uint32_t h0 = st->h[0], h1 = st->h[1], h2 = st->h[2], h3 = st->h[3], h4 = st->h[4];
	uint64_t d0, d1, d2, d3;
	uint32_t c;

	while (bytes >= poly1305_block_size) {
		/* add the block, with 2^128 above it unless it is the padded last one */
		h0 = (uint32_t)(d0 = (uint64_t)h0 + poly1305_load32(m + 0));
		h1 = (uint32_t)(d1 = (uint64_t)h1 + (d0 >> 32) + poly1305_load32(m + 4));
		h2 = (uint32_t)(d2 = (uint64_t)h2 + (d1 >> 32) + poly1305_load32(m + 8));
		h3 = (uint32_t)(d3 = (uint64_t)h3 + (d2 >> 32) + poly1305_load32(m + 12));
		h4 += (uint32_t)(d3 >> 32) + padbit;

		/* multiply by r; terms at 2^128 and above are folded through s */
		d0 = ((uint64_t)h0 * r0) + ((uint64_t)h1 * s3) + ((uint64_t)h2 * s2) + ((uint64_t)h3 * s1);
		d1 = ((uint64_t)h0 * r1) + ((uint64_t)h1 * r0) + ((uint64_t)h2 * s3) + ((uint64_t)h3 * s2) + (h4 * s1);
		d2 = ((uint64_t)h0 * r2) + ((uint64_t)h1 * r1) + ((uint64_t)h2 * r0) + ((uint64_t)h3 * s3) + (h4 * s2);
		d3 = ((uint64_t)h0 * r3) + ((uint64_t)h1 * r2) + ((uint64_t)h2 * r1) + ((uint64_t)h3 * r0) + (h4 * s3);
		h4 = h4 * r0;

		/* carry the columns into 32-bit words */
		h0 = (uint32_t)d0;
		h1 = (uint32_t)(d1 += d0 >> 32);
		h2 = (uint32_t)(d2 += d1 >> 32);
		h3 = (uint32_t)(d3 += d2 >> 32);
		h4 += (uint32_t)(d3 >> 32);
		/* fold bits 130 and up back in as 5 * (h >> 130), leaving h4 < 4 plus a carry */
		c = (h4 >> 2) + (h4 & ~3U);
		h4 &= 3;
		h0 += c;
		h1 += (c = (h0 < c));
		h2 += (c = (h1 < c));
		h3 += (c = (h2 < c));
		h4 += (h3 < c);

		m += poly1305_block_size;
		bytes -= poly1305_block_size;
	}

	st->h[0] = h0;
	st->h[1] = h1;
	st->h[2] = h2;
	st->h[3] = h3;
	st->h[4] = h4;
}

void
poly1305_finish(poly1305_context *ctx, unsigned char mac[16]) {
	poly1305_state_internal_t *st = (poly1305_state_internal_t *)ctx;
	uint32_t h0, h1, h2, h3, h4;
	uint32_t g0, g1, g2, g3, g4;
	uint64_t t;
	uint32_t mask;

	/* process the remaining block */
	if (st->leftover) {
		size_t i = st->leftover;
		st->buffer[i++] = 1;
		for (; i < poly1305_block_size; i++)
			st->buffer[i] = 0;
		st->final = 1;
		poly1305_blocks(st, st->buffer, poly1305_block_size);
	}

	h0 = st->h[0];
	h1 = st->h[1];
	h2 = st->h[2];
	h3 = st->h[3];
	h4 = st->h[4];

	/* h is below 2p here; g = h + 5 reaches 2^130 exactly when h >= p */
	g0 = (uint32_t)(t = (uint64_t)h0 + 5);
	g1 = (uint32_t)(t = (uint64_t)h1 + (t >> 32));
	g2 = (uint32_t)(t = (uint64_t)h2 + (t >> 32));
	g3 = (uint32_t)(t = (uint64_t)h3 + (t >> 32));
	g4 = h4 + (uint32_t)(t >> 32);

	/* then h mod p is the low 130 bits of g; choose without branching */
	mask = 0 - (g4 >> 2);
	g0 &= mask;
	g1 &= mask;
	g2 &= mask;
	g3 &= mask;
	mask = ~mask;
	h0 = (h0 & mask) | g0;
	h1 = (h1 & mask) | g1;
	h2 = (h2 & mask) | g2;
	h3 = (h3 & mask) | g3;

	/* tag = (h + pad) mod 2^128 */
	h0 = (uint32_t)(t = (uint64_t)h0 + st->pad[0]);
	h1 = (uint32_t)(t = (uint64_t)h1 + (t >> 32) + st->pad[1]);
	h2 = (uint32_t)(t = (uint64_t)h2 + (t >> 32) + st->pad[2]);
	h3 = (uint32_t)(t = (uint64_t)h3 + (t >> 32) + st->pad[3]);

	poly1305_store32(mac + 0, h0);
	poly1305_store32(mac + 4, h1);
	poly1305_store32(mac + 8, h2);
	poly1305_store32(mac + 12, h3);

	/* clear the key and accumulator */
	memset(st, 0, sizeof(*st));
}
