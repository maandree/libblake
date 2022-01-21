/* See LICENSE file for copyright and license details. */
#include "common.h"

static uint_least32_t
decode_uint32_le(const unsigned char *data)
{
	/* This is perfectly optimised by the compiler */
	return (((uint_least32_t)(data[0] & 255)) <<  0) |
	       (((uint_least32_t)(data[1] & 255)) <<  8) |
	       (((uint_least32_t)(data[2] & 255)) << 16) |
	       (((uint_least32_t)(data[3] & 255)) << 24);
}

static uint_least32_t
rotate_right(uint_least32_t x, int n)
{
	/* This is perfectly optimised by the compiler */
	return ((x >> n) | (x << (32 - n))) & UINT_LEAST32_C(0xFFFFffff);
}

void
libblake_internal_blake2s_compress(struct libblake_blake2s_state *state, const unsigned char *data)
{
	uint_least32_t v[16], m[16];

	memcpy(v, state->h, sizeof(state->h));
	v[8] = UINT_LEAST32_C(0x6A09E667);
	v[9] = UINT_LEAST32_C(0xBB67AE85);
	v[A] = UINT_LEAST32_C(0x3C6EF372);
	v[B] = UINT_LEAST32_C(0xA54FF53A);
	v[C] = UINT_LEAST32_C(0x510E527F) ^ state->t[0];
	v[D] = UINT_LEAST32_C(0x9B05688C) ^ state->t[1];
	v[E] = UINT_LEAST32_C(0x1F83D9AB) ^ state->f[0];
	v[F] = UINT_LEAST32_C(0x5BE0CD19) ^ state->f[1];

	m[0] = decode_uint32_le(&data[0 * 4]);
	m[1] = decode_uint32_le(&data[1 * 4]);
	m[2] = decode_uint32_le(&data[2 * 4]);
	m[3] = decode_uint32_le(&data[3 * 4]);
	m[4] = decode_uint32_le(&data[4 * 4]);
	m[5] = decode_uint32_le(&data[5 * 4]);
	m[6] = decode_uint32_le(&data[6 * 4]);
	m[7] = decode_uint32_le(&data[7 * 4]);
	m[8] = decode_uint32_le(&data[8 * 4]);
	m[9] = decode_uint32_le(&data[9 * 4]);
	m[A] = decode_uint32_le(&data[A * 4]);
	m[B] = decode_uint32_le(&data[B * 4]);
	m[C] = decode_uint32_le(&data[C * 4]);
	m[D] = decode_uint32_le(&data[D * 4]);
	m[E] = decode_uint32_le(&data[E * 4]);
	m[F] = decode_uint32_le(&data[F * 4]);

#define G2S(mj, mk, a, b, c, d)\
	a = (a + b + mj) & UINT_LEAST32_C(0xFFFFffff);\
	d = rotate_right(d ^ a, 16);\
	c = (c + d) & UINT_LEAST32_C(0xFFFFffff);\
	b = rotate_right(b ^ c, 12);\
	a = (a + b + mk) & UINT_LEAST32_C(0xFFFFffff);\
	d = rotate_right(d ^ a, 8);\
	c = (c + d) & UINT_LEAST32_C(0xFFFFffff);\
	b = rotate_right(b ^ c, 7)

#define ROUND2S(S0, S1, S2, S3, S4, S5, S6, S7, S8, S9, SA, SB, SC, SD, SE, SF)\
	G2S(m[S0], m[S1], v[0], v[4], v[8], v[C]);\
	G2S(m[S2], m[S3], v[1], v[5], v[9], v[D]);\
	G2S(m[S4], m[S5], v[2], v[6], v[A], v[E]);\
	G2S(m[S6], m[S7], v[3], v[7], v[B], v[F]);\
	G2S(m[S8], m[S9], v[0], v[5], v[A], v[F]);\
	G2S(m[SA], m[SB], v[1], v[6], v[B], v[C]);\
	G2S(m[SC], m[SD], v[2], v[7], v[8], v[D]);\
	G2S(m[SE], m[SF], v[3], v[4], v[9], v[E])

	ROUND2S(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, A, B, C, D, E, F);
	ROUND2S(E, A, 4, 8, 9, F, D, 6, 1, C, 0, 2, B, 7, 5, 3);
	ROUND2S(B, 8, C, 0, 5, 2, F, D, A, E, 3, 6, 7, 1, 9, 4);
	ROUND2S(7, 9, 3, 1, D, C, B, E, 2, 6, 5, A, 4, 0, F, 8);
	ROUND2S(9, 0, 5, 7, 2, 4, A, F, E, 1, B, C, 6, 8, 3, D);
	ROUND2S(2, C, 6, A, 0, B, 8, 3, 4, D, 7, 5, F, E, 1, 9);
	ROUND2S(C, 5, 1, F, E, D, 4, A, 0, 7, 6, 3, 9, 2, 8, B);
	ROUND2S(D, B, 7, E, C, 1, 3, 9, 5, 0, F, 4, 8, 6, 2, A);
	ROUND2S(6, F, E, 9, B, 3, 0, 8, C, 2, D, 7, 1, 4, A, 5);
	ROUND2S(A, 2, 8, 4, 7, 6, 1, 5, F, B, 9, E, 3, C, D, 0);

	state->h[0] ^= v[0] ^ v[8];
	state->h[1] ^= v[1] ^ v[9];
	state->h[2] ^= v[2] ^ v[A];
	state->h[3] ^= v[3] ^ v[B];
	state->h[4] ^= v[4] ^ v[C];
	state->h[5] ^= v[5] ^ v[D];
	state->h[6] ^= v[6] ^ v[E];
	state->h[7] ^= v[7] ^ v[F];
}
