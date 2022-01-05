/* See LICENSE file for copyright and license details. */
#include "common.h"

static void
encode_uint64_be(unsigned char *out, uint_least64_t value)
{
	out[0] = (unsigned char)((value >> 56) & 255);
	out[1] = (unsigned char)((value >> 48) & 255);
	out[2] = (unsigned char)((value >> 40) & 255);
	out[3] = (unsigned char)((value >> 32) & 255);
	out[4] = (unsigned char)((value >> 24) & 255);
	out[5] = (unsigned char)((value >> 16) & 255);
	out[6] = (unsigned char)((value >>  8) & 255);
	out[7] = (unsigned char)((value >>  0) & 255);
}

void
libblake_internal_blakeb_digest(struct libblake_blakeb_state *state, unsigned char *data, size_t len,
                                size_t bits, const char *suffix, unsigned char *output, size_t words_out)
{
	size_t r, i;
	unsigned char pad;
	uint_least64_t t0, t1;

	len += bits >> 3;
	bits &= 7;
	if (suffix) {
		while (*suffix) {
			data[len] |= (unsigned char)((*suffix++ & 1) << bits++);
			if (bits == 8) {
				bits = 0;
				data[++len] = 0;
			}
		}
	}

	r = libblake_internal_blakeb_update(state, data, len);
	data = &data[r];
	len -= r;

	pad = 0x80 >> bits;
	data[len] &= (unsigned char)(255U - (pad - 1U));
	data[len] |= pad;
	bits += len << 3;

	t0 = state->t[0] + (uint_least64_t)bits;
	t1 = state->t[1];

	if (!bits) {
		state->t[0] = UINT_LEAST64_C(0xFFFFffffFFFFfc00);
		state->t[1] = UINT_LEAST64_C(0xFFFFffffFFFFffff);
	} else if (!state->t[0]) {
		state->t[0] = UINT_LEAST64_C(0xFFFFffffFFFFfc00) + (uint_least64_t)bits;
		state->t[1] = (state->t[1] - 1) & UINT_LEAST64_C(0xFFFFffffFFFFffff);
	} else {
		state->t[1] -= (uint_least64_t)(1024U - bits);
	}

	if (bits < 1024 - (1 + 2 * 64)) {
		memset(&data[len + 1], 0, (1024 - 2 * 64) / 8 - 1 - len);
	} else {
		memset(&data[len + 1], 0, 1024 / 8 - 1 - len);
		data += libblake_internal_blakeb_update(state, data, 1024 / 8);
		state->t[0] = UINT_LEAST64_C(0xFFFFffffFFFFfc00);
		state->t[1] = UINT_LEAST64_C(0xFFFFffffFFFFffff);
		memset(data, 0, (1024 - 2 * 64) / 8 - len);
	}
	if (words_out == 8)
		data[(1024 - 2 * 64) / 8 - 1] |= 1;
	encode_uint64_be(&data[(1024 - 2 * 64) / 8], t1);
	encode_uint64_be(&data[(1024 - 1 * 64) / 8], t0);
	libblake_internal_blakeb_update(state, data, 1024 / 8);

	for (i = 0; i < words_out; i++)
		encode_uint64_be(&output[i * 8], state->h[i]);
}
