/* See LICENSE file for copyright and license details. */
#include "common.h"

void
libblake_blake384_digest(struct libblake_blake384_state *state, void *data, size_t len, size_t bits,
                         const char *suffix, unsigned char output[static LIBBLAKE_BLAKE384_OUTPUT_SIZE])
{
	libblake_internal_blakeb_digest(&state->b, data, len, bits, suffix, output, 385 / 64);
}
