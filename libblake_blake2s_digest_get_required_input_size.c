/* See LICENSE file for copyright and license details. */
#include "common.h"

size_t
libblake_blake2s_digest_get_required_input_size(size_t len)
{
	size_t blocks, rem;
	blocks = len >> 6;
	rem = len & 63;
	if (rem)
		blocks += 1;
	return blocks << 6;
}
