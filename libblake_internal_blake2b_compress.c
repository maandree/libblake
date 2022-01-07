/* See LICENSE file for copyright and license details. */
#include "common.h"

#define A 10
#define B 11
#define C 12
#define D 13
#define E 14
#define F 15

static uint_least64_t
decode_uint64_le(const unsigned char *data)
{
	return (((uint_least64_t)(data[0] & 255)) <<  0) |
	       (((uint_least64_t)(data[1] & 255)) <<  8) |
	       (((uint_least64_t)(data[2] & 255)) << 16) |
	       (((uint_least64_t)(data[3] & 255)) << 24) |
	       (((uint_least64_t)(data[4] & 255)) << 32) |
	       (((uint_least64_t)(data[5] & 255)) << 40) |
	       (((uint_least64_t)(data[6] & 255)) << 48) |
	       (((uint_least64_t)(data[7] & 255)) << 56);
}

static uint_least64_t
rotate_right(uint_least64_t x, int n)
{
	return ((x >> n) | (x << (64 - n))) & UINT_LEAST64_C(0xFFFFffffFFFFffff);
}

void
libblake_internal_blake2b_compress(struct libblake_blake2b_state *state, const unsigned char *data)
{
	uint_least64_t v[16], m[16];

	memcpy(v, state->h, sizeof(state->h));
	v[8] = UINT_LEAST64_C(0x6A09E667F3BCC908);
	v[9] = UINT_LEAST64_C(0xBB67AE8584CAA73B);
	v[A] = UINT_LEAST64_C(0x3C6EF372FE94F82B);
	v[B] = UINT_LEAST64_C(0xA54FF53A5F1D36F1);
	v[C] = UINT_LEAST64_C(0x510E527FADE682D1) ^ state->t[0];
	v[D] = UINT_LEAST64_C(0x9B05688C2B3E6C1F) ^ state->t[1];
	v[E] = UINT_LEAST64_C(0x1F83D9ABFB41BD6B) ^ state->f[0];
	v[F] = UINT_LEAST64_C(0x5BE0CD19137E2179) ^ state->f[1];

	m[0] = decode_uint64_le(&data[0 * 8]);
	m[1] = decode_uint64_le(&data[1 * 8]);
	m[2] = decode_uint64_le(&data[2 * 8]);
	m[3] = decode_uint64_le(&data[3 * 8]);
	m[4] = decode_uint64_le(&data[4 * 8]);
	m[5] = decode_uint64_le(&data[5 * 8]);
	m[6] = decode_uint64_le(&data[6 * 8]);
	m[7] = decode_uint64_le(&data[7 * 8]);
	m[8] = decode_uint64_le(&data[8 * 8]);
	m[9] = decode_uint64_le(&data[9 * 8]);
	m[A] = decode_uint64_le(&data[A * 8]);
	m[B] = decode_uint64_le(&data[B * 8]);
	m[C] = decode_uint64_le(&data[C * 8]);
	m[D] = decode_uint64_le(&data[D * 8]);
	m[E] = decode_uint64_le(&data[E * 8]);
	m[F] = decode_uint64_le(&data[F * 8]);

#define G2B(mj, mk, a, b, c, d)\
	a = (a + b + mj) & UINT_LEAST64_C(0xFFFFffffFFFFffff);\
	d = rotate_right(d ^ a, 32);\
	c = (c + d) & UINT_LEAST64_C(0xFFFFffffFFFFffff);\
	b = rotate_right(b ^ c, 24);\
	a = (a + b + mk) & UINT_LEAST64_C(0xFFFFffffFFFFffff);\
	d = rotate_right(d ^ a, 16);\
	c = (c + d) & UINT_LEAST64_C(0xFFFFffffFFFFffff);\
	b = rotate_right(b ^ c, 63)

#define ROUND2B(S0, S1, S2, S3, S4, S5, S6, S7, S8, S9, SA, SB, SC, SD, SE, SF)\
	G2B(m[S0], m[S1], v[0], v[4], v[8], v[C]);\
	G2B(m[S2], m[S3], v[1], v[5], v[9], v[D]);\
	G2B(m[S4], m[S5], v[2], v[6], v[A], v[E]);\
	G2B(m[S6], m[S7], v[3], v[7], v[B], v[F]);\
	G2B(m[S8], m[S9], v[0], v[5], v[A], v[F]);\
	G2B(m[SA], m[SB], v[1], v[6], v[B], v[C]);\
	G2B(m[SC], m[SD], v[2], v[7], v[8], v[D]);\
	G2B(m[SE], m[SF], v[3], v[4], v[9], v[E])

	ROUND2B(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, A, B, C, D, E, F);
	ROUND2B(E, A, 4, 8, 9, F, D, 6, 1, C, 0, 2, B, 7, 5, 3);
	ROUND2B(B, 8, C, 0, 5, 2, F, D, A, E, 3, 6, 7, 1, 9, 4);
	ROUND2B(7, 9, 3, 1, D, C, B, E, 2, 6, 5, A, 4, 0, F, 8);
	ROUND2B(9, 0, 5, 7, 2, 4, A, F, E, 1, B, C, 6, 8, 3, D);
	ROUND2B(2, C, 6, A, 0, B, 8, 3, 4, D, 7, 5, F, E, 1, 9);
	ROUND2B(C, 5, 1, F, E, D, 4, A, 0, 7, 6, 3, 9, 2, 8, B);
	ROUND2B(D, B, 7, E, C, 1, 3, 9, 5, 0, F, 4, 8, 6, 2, A);
	ROUND2B(6, F, E, 9, B, 3, 0, 8, C, 2, D, 7, 1, 4, A, 5);
	ROUND2B(A, 2, 8, 4, 7, 6, 1, 5, F, B, 9, E, 3, C, D, 0);
	ROUND2B(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, A, B, C, D, E, F);
	ROUND2B(E, A, 4, 8, 9, F, D, 6, 1, C, 0, 2, B, 7, 5, 3);

	state->h[0] ^= v[0] ^ v[8];
	state->h[1] ^= v[1] ^ v[9];
	state->h[2] ^= v[2] ^ v[A];
	state->h[3] ^= v[3] ^ v[B];
	state->h[4] ^= v[4] ^ v[C];
	state->h[5] ^= v[5] ^ v[D];
	state->h[6] ^= v[6] ^ v[E];
	state->h[7] ^= v[7] ^ v[F];
}
