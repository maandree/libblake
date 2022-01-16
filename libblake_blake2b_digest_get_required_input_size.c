/* See LICENSE file for copyright and license details. */
#include "common.h"

size_t
libblake_blake2b_digest_get_required_input_size(size_t len)
{
	size_t blocks, rem;
	blocks = len >> 7;
	rem = len & 127;
	if (rem || !blocks)
		blocks += 1;
	return blocks << 7;
}
