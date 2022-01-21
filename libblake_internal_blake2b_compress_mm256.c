/* See LICENSE file for copyright and license details. */
#include "common.h"
#include <immintrin.h>

static __m256i ror24, ror16;

static __m256i
load_m256i(size_t a, size_t b, size_t c, size_t d, const uint_least64_t vec[])
{
	return _mm256_set_epi64x((int_least64_t)vec[d], (int_least64_t)vec[c],
	                         (int_least64_t)vec[b], (int_least64_t)vec[a]);
}

void
libblake_internal_blake2b_compress_mm256_init(void)
{
#define X(A, B, C, D, E, F, G, H, P) (A + P), (B + P), (C + P), (D + P), (E + P), (F + P), (G + P), (H + P)
	ror24 = _mm256_setr_epi8(X(3, 4, 5, 6, 7, 0, 1, 2,  0),
	                         X(3, 4, 5, 6, 7, 0, 1, 2,  8),
	                         X(3, 4, 5, 6, 7, 0, 1, 2, 16),
	                         X(3, 4, 5, 6, 7, 0, 1, 2, 24));
	ror16 = _mm256_setr_epi8(X(2, 3, 4, 5, 6, 7, 0, 1,  0),
	                         X(2, 3, 4, 5, 6, 7, 0, 1,  8),
	                         X(2, 3, 4, 5, 6, 7, 0, 1, 16),
	                         X(2, 3, 4, 5, 6, 7, 0, 1, 24));
#undef X
}

void
libblake_internal_blake2b_compress(struct libblake_blake2b_state *state, const unsigned char *data)
{
	static const uint_least64_t _Alignas(__m256i) initvec[] = {
		UINT_LEAST64_C(0x6A09E667F3BCC908), UINT_LEAST64_C(0xBB67AE8584CAA73B),
		UINT_LEAST64_C(0x3C6EF372FE94F82B), UINT_LEAST64_C(0xA54FF53A5F1D36F1),
		UINT_LEAST64_C(0x510E527FADE682D1), UINT_LEAST64_C(0x9B05688C2B3E6C1F),
		UINT_LEAST64_C(0x1F83D9ABFB41BD6B), UINT_LEAST64_C(0x5BE0CD19137E2179),
	};
	__m256i v[4], mj, mk, tf, h[2];

	tf = _mm256_load_si256((const __m256i *)state->t);
	v[0] = h[0] = _mm256_load_si256((const __m256i *)&state->h[0]);
	v[1] = h[1] = _mm256_load_si256((const __m256i *)&state->h[4]);
	v[2] = _mm256_load_si256((const __m256i *)&initvec[0]);
	v[3] = _mm256_load_si256((const __m256i *)&initvec[4]);
	v[3] = _mm256_xor_si256(v[3], tf);

#define G2B(j1, k1, j2, k2, j3, k3, j4, k4, shift)\
	do {\
		mj = load_m256i(j1, j2, j3, j4, (const void *)data);\
		mk = load_m256i(k1, k2, k3, k4, (const void *)data);\
		if (shift) {\
			v[1] = _mm256_permute4x64_epi64(v[1], _MM_SHUFFLE(0, 3, 2, 1));\
			v[2] = _mm256_permute4x64_epi64(v[2], _MM_SHUFFLE(1, 0, 3, 2));\
			v[3] = _mm256_permute4x64_epi64(v[3], _MM_SHUFFLE(2, 1, 0, 3));\
		}\
		v[0] = _mm256_add_epi64(v[0], v[1]);\
		v[0] = _mm256_add_epi64(v[0], mj);\
		v[3] = _mm256_xor_si256(v[3], v[0]);\
		v[3] = _mm256_shuffle_epi32(v[3], _MM_SHUFFLE(2, 3, 0, 1));\
		v[2] = _mm256_add_epi64(v[2], v[3]);\
		v[1] = _mm256_xor_si256(v[1], v[2]);\
		v[1] = _mm256_shuffle_epi8(v[1], ror24);\
		v[0] = _mm256_add_epi64(v[0], v[1]);\
		v[0] = _mm256_add_epi64(v[0], mk);\
		v[3] = _mm256_xor_si256(v[3], v[0]);\
		v[3] = _mm256_shuffle_epi8(v[3], ror16);\
		v[2] = _mm256_add_epi64(v[2], v[3]);\
		v[1] = _mm256_xor_si256(v[1], v[2]);\
		v[1] = _mm256_xor_si256(_mm256_srli_epi64(v[1], 63),\
		                        _mm256_add_epi64(v[1], v[1]));\
		if (shift) {\
			v[1] = _mm256_permute4x64_epi64(v[1], _MM_SHUFFLE(2, 1, 0, 3));\
			v[2] = _mm256_permute4x64_epi64(v[2], _MM_SHUFFLE(1, 0, 3, 2));\
			v[3] = _mm256_permute4x64_epi64(v[3], _MM_SHUFFLE(0, 3, 2, 1));\
		}\
	} while (0)

#define ROUND2B(S0, S1, S2, S3, S4, S5, S6, S7, S8, S9, SA, SB, SC, SD, SE, SF)\
	G2B(S0, S1, S2, S3, S4, S5, S6, S7, 0);\
	G2B(S8, S9, SA, SB, SC, SD, SE, SF, 1)

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

	v[0] = _mm256_xor_si256(v[0], v[2]);
	v[1] = _mm256_xor_si256(v[1], v[3]);
	v[0] = _mm256_xor_si256(v[0], h[0]);
	v[1] = _mm256_xor_si256(v[1], h[1]);
	_mm256_store_si256((__m256i *)&state->h[0], v[0]);
	_mm256_store_si256((__m256i *)&state->h[4], v[1]);
}
