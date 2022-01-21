/* See LICENSE file for copyright and license details. */
#include "common.h"
#include <immintrin.h>

static __m128i ror24, ror16;

static __m128i
load_m128i(size_t a, size_t b, __m128i vec[])
{
	if (a & 1) {
		if (b & 1)
			return _mm_unpackhi_epi64(vec[a / 2], vec[b / 2]);
		else
			return _mm_shuffle_epi32(_mm_blend_epi32(vec[a / 2], vec[b / 2], 0x3), _MM_SHUFFLE(1, 0, 3, 2));
	} else {
		if (a + 1 == b)
			return vec[a / 2];
		else if (b & 1)
			return _mm_blend_epi32(vec[b / 2], vec[a / 2], 0x3);
		else
			return _mm_unpacklo_epi64(vec[a / 2], vec[b / 2]);
	}
}

static __m128i
load_high_and_low(__m128i hi, __m128i lo)
{
	return _mm_shuffle_epi32(_mm_blend_epi32(hi, lo, 0x3), _MM_SHUFFLE(1, 0, 3, 2));
}

static void
store_high_low_and_low_high(__m128i *hip, __m128i *lop, __m128i val1, __m128i val2)
{
	*hip = load_high_and_low(val1, val2);
	*lop = load_high_and_low(val2, val1);
}

void
libblake_internal_blake2b_compress_mm128_init(void)
{
#define X(A, B, C, D, E, F, G, H, P) (A + P), (B + P), (C + P), (D + P), (E + P), (F + P), (G + P), (H + P)
	ror24 = _mm_setr_epi8(X(3, 4, 5, 6, 7, 0, 1, 2,  0),
	                      X(3, 4, 5, 6, 7, 0, 1, 2,  8));
	ror16 = _mm_setr_epi8(X(2, 3, 4, 5, 6, 7, 0, 1,  0),
	                      X(2, 3, 4, 5, 6, 7, 0, 1,  8));
#undef X
}

void
libblake_internal_blake2b_compress(struct libblake_blake2b_state *state, const unsigned char *data)
{
	static const uint_least64_t _Alignas(__m128i) initvec[] = {
		UINT_LEAST64_C(0x6A09E667F3BCC908), UINT_LEAST64_C(0xBB67AE8584CAA73B),
		UINT_LEAST64_C(0x3C6EF372FE94F82B), UINT_LEAST64_C(0xA54FF53A5F1D36F1),
		UINT_LEAST64_C(0x510E527FADE682D1), UINT_LEAST64_C(0x9B05688C2B3E6C1F),
		UINT_LEAST64_C(0x1F83D9ABFB41BD6B), UINT_LEAST64_C(0x5BE0CD19137E2179),
	};
	__m128i v[8], mj, mk, t, f, h[4], m[8], x, y;

	t = _mm_load_si128((const __m128i *)state->t);
	f = _mm_load_si128((const __m128i *)state->f);
	v[0] = h[0] = _mm_load_si128((const __m128i *)&state->h[0]);
	v[1] = h[1] = _mm_load_si128((const __m128i *)&state->h[2]);
	v[2] = h[2] = _mm_load_si128((const __m128i *)&state->h[4]);
	v[3] = h[3] = _mm_load_si128((const __m128i *)&state->h[6]);
	v[4] = _mm_load_si128((const __m128i *)&initvec[0]);
	v[5] = _mm_load_si128((const __m128i *)&initvec[2]);
	v[6] = _mm_load_si128((const __m128i *)&initvec[4]);
	v[7] = _mm_load_si128((const __m128i *)&initvec[6]);
	v[6] = _mm_xor_si128(v[6], t);
	v[7] = _mm_xor_si128(v[7], f);

	if (LIKELY((uintptr_t)data % 16 == 0)) {
		m[0] = _mm_load_si128((const __m128i *)&data[0 * 16]);
		m[1] = _mm_load_si128((const __m128i *)&data[1 * 16]);
		m[2] = _mm_load_si128((const __m128i *)&data[2 * 16]);
		m[3] = _mm_load_si128((const __m128i *)&data[3 * 16]);
		m[4] = _mm_load_si128((const __m128i *)&data[4 * 16]);
		m[5] = _mm_load_si128((const __m128i *)&data[5 * 16]);
		m[6] = _mm_load_si128((const __m128i *)&data[6 * 16]);
		m[7] = _mm_load_si128((const __m128i *)&data[7 * 16]);
	} else {
		m[0] = _mm_loadu_si128((const __m128i *)&data[0 * 16]);
		m[1] = _mm_loadu_si128((const __m128i *)&data[1 * 16]);
		m[2] = _mm_loadu_si128((const __m128i *)&data[2 * 16]);
		m[3] = _mm_loadu_si128((const __m128i *)&data[3 * 16]);
		m[4] = _mm_loadu_si128((const __m128i *)&data[4 * 16]);
		m[5] = _mm_loadu_si128((const __m128i *)&data[5 * 16]);
		m[6] = _mm_loadu_si128((const __m128i *)&data[6 * 16]);
		m[7] = _mm_loadu_si128((const __m128i *)&data[7 * 16]);
	}

#define G2B(j1, k1, j2, k2, a, b, c, d, shift)\
	mj = load_m128i(j1, j2, m);\
	mk = load_m128i(k1, k2, m);\
	v[a] = _mm_add_epi64(v[a], v[b]);\
	v[a] = _mm_add_epi64(v[a], mj);\
	v[d] = _mm_xor_si128(v[d], v[a]);\
	v[d] = _mm_shuffle_epi32(v[d], _MM_SHUFFLE(2, 3, 0, 1));\
	v[c] = _mm_add_epi64(v[c], v[d]);\
	v[b] = _mm_xor_si128(v[b], v[c]);\
	v[b] = _mm_shuffle_epi8(v[b], ror24);\
	v[a] = _mm_add_epi64(v[a], v[b]);\
	v[a] = _mm_add_epi64(v[a], mk);\
	v[d] = _mm_xor_si128(v[d], v[a]);\
	v[d] = _mm_shuffle_epi8(v[d], ror16);\
	v[c] = _mm_add_epi64(v[c], v[d]);\
	v[b] = _mm_xor_si128(v[b], v[c]);\
	v[b] = _mm_xor_si128(_mm_srli_epi64(v[b], 63),\
	                     _mm_add_epi64(v[b], v[b]))

#define ROUND2B(S0, S1, S2, S3, S4, S5, S6, S7, S8, S9, SA, SB, SC, SD, SE, SF)\
	G2B(S0, S1, S2, S3, 0, 2, 4, 6, 0);\
	G2B(S4, S5, S6, S7, 1, 3, 5, 7, 0);\
	x = v[2];\
	y = v[3];\
	v[2] = load_high_and_low(x, y);\
	v[3] = load_high_and_low(y, x);\
	x = v[6];\
	y = v[7];\
	v[6] = load_high_and_low(y, x);\
	v[7] = load_high_and_low(x, y);\
	G2B(S8, S9, SA, SB, 0, 2, 5, 6, 1);\
	G2B(SC, SD, SE, SF, 1, 3, 4, 7, 2);\
	x = v[2];\
	y = v[3];\
	store_high_low_and_low_high(&v[2], &v[3], y, x);\
	x = v[6];\
	y = v[7];\
	store_high_low_and_low_high(&v[7], &v[6], y, x)

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

	v[0] = _mm_xor_si128(_mm_xor_si128(v[0], v[4]), h[0]);
	v[1] = _mm_xor_si128(_mm_xor_si128(v[1], v[5]), h[1]);
	v[2] = _mm_xor_si128(_mm_xor_si128(v[2], v[6]), h[2]);
	v[3] = _mm_xor_si128(_mm_xor_si128(v[3], v[7]), h[3]);
	_mm_store_si128((__m128i *)&state->h[0], v[0]);
	_mm_store_si128((__m128i *)&state->h[2], v[1]);
	_mm_store_si128((__m128i *)&state->h[4], v[2]);
	_mm_store_si128((__m128i *)&state->h[6], v[3]);
}
