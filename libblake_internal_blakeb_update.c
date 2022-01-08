/* See LICENSE file for copyright and license details. */
#include "common.h"

#define CB0 UINT_LEAST64_C(0x243F6A8885A308D3)
#define CB1 UINT_LEAST64_C(0x13198A2E03707344)
#define CB2 UINT_LEAST64_C(0xA4093822299F31D0)
#define CB3 UINT_LEAST64_C(0x082EFA98EC4E6C89)
#define CB4 UINT_LEAST64_C(0x452821E638D01377)
#define CB5 UINT_LEAST64_C(0xBE5466CF34E90C6C)
#define CB6 UINT_LEAST64_C(0xC0AC29B7C97C50DD)
#define CB7 UINT_LEAST64_C(0x3F84D5B5B5470917)
#define CB8 UINT_LEAST64_C(0x9216D5D98979FB1B)
#define CB9 UINT_LEAST64_C(0xD1310BA698DFB5AC)
#define CBA UINT_LEAST64_C(0x2FFD72DBD01ADFB7)
#define CBB UINT_LEAST64_C(0xB8E1AFED6A267E96)
#define CBC UINT_LEAST64_C(0xBA7C9045F12C7F99)
#define CBD UINT_LEAST64_C(0x24A19947B3916CF7)
#define CBE UINT_LEAST64_C(0x0801F2E2858EFC16)
#define CBF UINT_LEAST64_C(0x636920D871574E69)

static uint_least64_t
decode_uint64_be(const unsigned char *data)
{
	return (((uint_least64_t)(data[0] & 255)) << 56) |
	       (((uint_least64_t)(data[1] & 255)) << 48) |
	       (((uint_least64_t)(data[2] & 255)) << 40) |
	       (((uint_least64_t)(data[3] & 255)) << 32) |
	       (((uint_least64_t)(data[4] & 255)) << 24) |
	       (((uint_least64_t)(data[5] & 255)) << 16) |
	       (((uint_least64_t)(data[6] & 255)) <<  8) |
	       (((uint_least64_t)(data[7] & 255)) <<  0);
}

static uint_least64_t
rotate_right(uint_least64_t x, int n)
{
	return ((x >> n) | (x << (64 - n))) & UINT_LEAST64_C(0xFFFFffffFFFFffff);
}

size_t
libblake_internal_blakeb_update(struct libblake_blakeb_state *state, const unsigned char *data, size_t len)
{
	size_t off = 0;
	struct libblake_blakeb_state s;
	uint_least64_t v[16], m[16];

	memcpy(&s, state, sizeof(s));

	for (; len - off >= 128; off += 128, data = &data[128]) {
		s.t[0] = (s.t[0] + 1024) & UINT_LEAST64_C(0xFFFFffffFFFFffff);
		if (s.t[0] < 1024)
			s.t[1] = (s.t[1] + 1) & UINT_LEAST64_C(0xFFFFffffFFFFffff);

		memcpy(v, s.h, sizeof(s.h));
		v[8] = s.s[0] ^ CB0;
		v[9] = s.s[1] ^ CB1;
		v[A] = s.s[2] ^ CB2;
		v[B] = s.s[3] ^ CB3;
		v[C] = s.t[0] ^ CB4;
		v[D] = s.t[0] ^ CB5;
		v[E] = s.t[1] ^ CB6;
		v[F] = s.t[1] ^ CB7;

		m[0] = decode_uint64_be(&data[0 * 8]);
		m[1] = decode_uint64_be(&data[1 * 8]);
		m[2] = decode_uint64_be(&data[2 * 8]);
		m[3] = decode_uint64_be(&data[3 * 8]);
		m[4] = decode_uint64_be(&data[4 * 8]);
		m[5] = decode_uint64_be(&data[5 * 8]);
		m[6] = decode_uint64_be(&data[6 * 8]);
		m[7] = decode_uint64_be(&data[7 * 8]);
		m[8] = decode_uint64_be(&data[8 * 8]);
		m[9] = decode_uint64_be(&data[9 * 8]);
		m[A] = decode_uint64_be(&data[A * 8]);
		m[B] = decode_uint64_be(&data[B * 8]);
		m[C] = decode_uint64_be(&data[C * 8]);
		m[D] = decode_uint64_be(&data[D * 8]);
		m[E] = decode_uint64_be(&data[E * 8]);
		m[F] = decode_uint64_be(&data[F * 8]);

#define GB(mj, mk, nj, nk, a, b, c, d)\
		a = (a + b + (mj ^ nk)) & UINT_LEAST64_C(0xFFFFffffFFFFffff);\
		d = rotate_right(d ^ a, 32);\
		c = (c + d) & UINT_LEAST64_C(0xFFFFffffFFFFffff);\
		b = rotate_right(b ^ c, 25);\
		a = (a + b + (mk ^ nj)) & UINT_LEAST64_C(0xFFFFffffFFFFffff);\
		d = rotate_right(d ^ a, 16);\
		c = (c + d) & UINT_LEAST64_C(0xFFFFffffFFFFffff);\
		b = rotate_right(b ^ c, 11)

#define ROUNDB(S0, S1, S2, S3, S4, S5, S6, S7, S8, S9, SA, SB, SC, SD, SE, SF)\
		GB(m[S0], m[S1], CB##S0, CB##S1, v[0], v[4], v[8], v[C]);\
		GB(m[S2], m[S3], CB##S2, CB##S3, v[1], v[5], v[9], v[D]);\
		GB(m[S4], m[S5], CB##S4, CB##S5, v[2], v[6], v[A], v[E]);\
		GB(m[S6], m[S7], CB##S6, CB##S7, v[3], v[7], v[B], v[F]);\
		GB(m[S8], m[S9], CB##S8, CB##S9, v[0], v[5], v[A], v[F]);\
		GB(m[SA], m[SB], CB##SA, CB##SB, v[1], v[6], v[B], v[C]);\
		GB(m[SC], m[SD], CB##SC, CB##SD, v[2], v[7], v[8], v[D]);\
		GB(m[SE], m[SF], CB##SE, CB##SF, v[3], v[4], v[9], v[E])

		ROUNDB(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, A, B, C, D, E, F);
		ROUNDB(E, A, 4, 8, 9, F, D, 6, 1, C, 0, 2, B, 7, 5, 3);
		ROUNDB(B, 8, C, 0, 5, 2, F, D, A, E, 3, 6, 7, 1, 9, 4);
		ROUNDB(7, 9, 3, 1, D, C, B, E, 2, 6, 5, A, 4, 0, F, 8);
		ROUNDB(9, 0, 5, 7, 2, 4, A, F, E, 1, B, C, 6, 8, 3, D);
		ROUNDB(2, C, 6, A, 0, B, 8, 3, 4, D, 7, 5, F, E, 1, 9);
		ROUNDB(C, 5, 1, F, E, D, 4, A, 0, 7, 6, 3, 9, 2, 8, B);
		ROUNDB(D, B, 7, E, C, 1, 3, 9, 5, 0, F, 4, 8, 6, 2, A);
		ROUNDB(6, F, E, 9, B, 3, 0, 8, C, 2, D, 7, 1, 4, A, 5);
		ROUNDB(A, 2, 8, 4, 7, 6, 1, 5, F, B, 9, E, 3, C, D, 0);
		ROUNDB(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, A, B, C, D, E, F);
		ROUNDB(E, A, 4, 8, 9, F, D, 6, 1, C, 0, 2, B, 7, 5, 3);
		ROUNDB(B, 8, C, 0, 5, 2, F, D, A, E, 3, 6, 7, 1, 9, 4);
		ROUNDB(7, 9, 3, 1, D, C, B, E, 2, 6, 5, A, 4, 0, F, 8);
		ROUNDB(9, 0, 5, 7, 2, 4, A, F, E, 1, B, C, 6, 8, 3, D);
		ROUNDB(2, C, 6, A, 0, B, 8, 3, 4, D, 7, 5, F, E, 1, 9);

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

	return off;
}
