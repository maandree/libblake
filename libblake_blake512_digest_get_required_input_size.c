/* See LICENSE file for copyright and license details. */
#include "common.h"

size_t
libblake_blake512_digest_get_required_input_size(size_t len, size_t bits, const char *suffix)
{
	bits += suffix ? strlen(suffix) : 0;
	len += bits >> 3;
	bits &= 7;
	bits += (len & 127) << 3;
	len &= ~(size_t)127;
	len += (size_t)128 << (bits >= 1024 - (1 + 2 * 64));
	return len;
}

