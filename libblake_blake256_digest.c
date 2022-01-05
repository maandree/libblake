/* See LICENSE file for copyright and license details. */
#include "common.h"

void
libblake_blake256_digest(struct libblake_blake256_state *state, void *data, size_t len, size_t bits,
                         const char *suffix, unsigned char output[static LIBBLAKE_BLAKE256_OUTPUT_SIZE])
{
	libblake_internal_blakes_digest(&state->s, data, len, bits, suffix, output, 256 / 32);
}
