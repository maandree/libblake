/* See LICENSE file for copyright and license details. */
#include "common.h"

#define A 10
#define B 11
#define C 12
#define D 13
#define E 14
#define F 15

#define CS0 UINT_LEAST32_C(0x243F6A88)
#define CS1 UINT_LEAST32_C(0x85A308D3)
#define CS2 UINT_LEAST32_C(0x13198A2E)
#define CS3 UINT_LEAST32_C(0x03707344)
#define CS4 UINT_LEAST32_C(0xA4093822)
#define CS5 UINT_LEAST32_C(0x299F31D0)
#define CS6 UINT_LEAST32_C(0x082EFA98)
#define CS7 UINT_LEAST32_C(0xEC4E6C89)
#define CS8 UINT_LEAST32_C(0x452821E6)
#define CS9 UINT_LEAST32_C(0x38D01377)
#define CSA UINT_LEAST32_C(0xBE5466CF)
#define CSB UINT_LEAST32_C(0x34E90C6C)
#define CSC UINT_LEAST32_C(0xC0AC29B7)
#define CSD UINT_LEAST32_C(0xC97C50DD)
#define CSE UINT_LEAST32_C(0x3F84D5B5)
#define CSF UINT_LEAST32_C(0xB5470917)

static uint_least32_t
decode_uint32_be(const unsigned char *data)
{
	return (((uint_least32_t)(data[0] & 255)) << 24) |
	       (((uint_least32_t)(data[1] & 255)) << 16) |
	       (((uint_least32_t)(data[2] & 255)) <<  8) |
	       (((uint_least32_t)(data[3] & 255)) <<  0);
}

static uint_least32_t
rotate_right(uint_least32_t x, int n)
{
	return ((x >> n) | (x << (32 - n))) & UINT_LEAST32_C(0xFFFFffff);
}

size_t
libblake_internal_blakes_update(struct libblake_blakes_state *state, const unsigned char *data, size_t len)
{
	size_t ret = 0;
	struct libblake_blakes_state s;
	uint_least32_t v[16], m[16];

	memcpy(&s, state, sizeof(s));

	for (; len - ret >= 64; ret += 64, data = &data[64]) {
		s.t[0] += 512;
		if ((s.t[0] & UINT_LEAST32_C(0xFFFFffff)) < 512)
			s.t[1] = (s.t[1] + 1) & UINT_LEAST32_C(0xFFFFffff);

		memcpy(v, s.h, sizeof(s.h));
		v[8]  = s.s[0] ^ CS0;
		v[9]  = s.s[1] ^ CS1;
		v[10] = s.s[2] ^ CS2;
		v[11] = s.s[3] ^ CS3;
		v[12] = s.t[0] ^ CS4;
		v[13] = s.t[0] ^ CS5;
		v[14] = s.t[1] ^ CS6;
		v[15] = s.t[1] ^ CS7;

		m[0] = decode_uint32_be(&data[0 * 4]);
		m[1] = decode_uint32_be(&data[1 * 4]);
		m[2] = decode_uint32_be(&data[2 * 4]);
		m[3] = decode_uint32_be(&data[3 * 4]);
		m[4] = decode_uint32_be(&data[4 * 4]);
		m[5] = decode_uint32_be(&data[5 * 4]);
		m[6] = decode_uint32_be(&data[6 * 4]);
		m[7] = decode_uint32_be(&data[7 * 4]);
		m[8] = decode_uint32_be(&data[8 * 4]);
		m[9] = decode_uint32_be(&data[9 * 4]);
		m[A] = decode_uint32_be(&data[A * 4]);
		m[B] = decode_uint32_be(&data[B * 4]);
		m[C] = decode_uint32_be(&data[C * 4]);
		m[D] = decode_uint32_be(&data[D * 4]);
		m[E] = decode_uint32_be(&data[E * 4]);
		m[F] = decode_uint32_be(&data[F * 4]);

#define GS(mj, mk, nj, nk, a, b, c, d)\
		a = (a + b + (mj ^ nk)) & UINT_LEAST32_C(0xFFFFffff);\
		d = rotate_right(d ^ a, 16);\
		c = (c + d) & UINT_LEAST32_C(0xFFFFffff);\
		b = rotate_right(b ^ c, 12);\
		a = (a + b + (mk ^ nj)) & UINT_LEAST32_C(0xFFFFffff);\
		d = rotate_right(d ^ a, 8);\
		c = (c + d) & UINT_LEAST32_C(0xFFFFffff);\
		b = rotate_right(b ^ c, 7)

#define ROUNDS(S0, S1, S2, S3, S4, S5, S6, S7, S8, S9, SA, SB, SC, SD, SE, SF)\
		GS(m[S0], m[S1], CS##S0, CS##S1, v[0], v[4], v[8], v[C]);\
                GS(m[S2], m[S3], CS##S2, CS##S3, v[1], v[5], v[9], v[D]);\
                GS(m[S4], m[S5], CS##S4, CS##S5, v[2], v[6], v[A], v[E]);\
                GS(m[S6], m[S7], CS##S6, CS##S7, v[3], v[7], v[B], v[F]);\
                GS(m[S8], m[S9], CS##S8, CS##S9, v[0], v[5], v[A], v[F]);\
                GS(m[SA], m[SB], CS##SA, CS##SB, v[1], v[6], v[B], v[C]);\
                GS(m[SC], m[SD], CS##SC, CS##SD, v[2], v[7], v[8], v[D]);\
                GS(m[SE], m[SF], CS##SE, CS##SF, v[3], v[4], v[9], v[E])

		ROUNDS(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, A, B, C, D, E, F);
		ROUNDS(E, A, 4, 8, 9, F, D, 6, 1, C, 0, 2, B, 7, 5, 3);
		ROUNDS(B, 8, C, 0, 5, 2, F, D, A, E, 3, 6, 7, 1, 9, 4);
		ROUNDS(7, 9, 3, 1, D, C, B, E, 2, 6, 5, A, 4, 0, F, 8);
		ROUNDS(9, 0, 5, 7, 2, 4, A, F, E, 1, B, C, 6, 8, 3, D);
		ROUNDS(2, C, 6, A, 0, B, 8, 3, 4, D, 7, 5, F, E, 1, 9);
		ROUNDS(C, 5, 1, F, E, D, 4, A, 0, 7, 6, 3, 9, 2, 8, B);
		ROUNDS(D, B, 7, E, C, 1, 3, 9, 5, 0, F, 4, 8, 6, 2, A);
		ROUNDS(6, F, E, 9, B, 3, 0, 8, C, 2, D, 7, 1, 4, A, 5);
		ROUNDS(A, 2, 8, 4, 7, 6, 1, 5, F, B, 9, E, 3, C, D, 0);
		ROUNDS(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, A, B, C, D, E, F);
		ROUNDS(E, A, 4, 8, 9, F, D, 6, 1, C, 0, 2, B, 7, 5, 3);
		ROUNDS(B, 8, C, 0, 5, 2, F, D, A, E, 3, 6, 7, 1, 9, 4);
		ROUNDS(7, 9, 3, 1, D, C, B, E, 2, 6, 5, A, 4, 0, F, 8);

		s.h[0] ^= s.s[0] ^ v[0] ^ v[8];
		s.h[1] ^= s.s[1] ^ v[1] ^ v[9];
		s.h[2] ^= s.s[2] ^ v[2] ^ v[A];
		s.h[3] ^= s.s[3] ^ v[3] ^ v[B];
		s.h[4] ^= s.s[0] ^ v[4] ^ v[C];
		s.h[5] ^= s.s[1] ^ v[5] ^ v[D];
		s.h[6] ^= s.s[2] ^ v[6] ^ v[E];
		s.h[7] ^= s.s[3] ^ v[7] ^ v[F];
	}

	memcpy(state, &s, sizeof(s));

	return ret;
}
