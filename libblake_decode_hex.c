/* See LICENSE file for copyright and license details. */
#include "common.h"

size_t
libblake_decode_hex(const char *data, size_t n, void *out_)
{
	unsigned char *out = out_, value;
	size_t i, j = 0;
	int odd = 0;

	if (!out) {
		for (i = 0; i < n && data[i]; i++) {
			if (isxdigit(data[i])) {
				j += (size_t)odd;
				odd ^= 1;
			}
		}
		return j;
	}

	for (i = 0; i < n && data[i]; i++) {
		if (isxdigit(data[i])) {
			value = (unsigned char)((data[i] & 15) + (data[i] > '9' ? 9 : 0));
			if (!odd) {
				out[j] = (unsigned char)(value << 4);
				odd = 1;
			} else {
				out[j++] |= value;
				odd = 0;
			}
		}
	}

	return j;
}
