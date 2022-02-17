/* See LICENSE file for copyright and license details. */
#include "common.h"
#include <stdatomic.h>

#if defined(__GNUC__)
__attribute__((__constructor__)) /* ignored if statically linked, so this function shall
                                  * by the application, we just use the constructor (init)
                                  * attribute in case that is forgotten, as it will only
                                  * improve performance, but the library with function
                                  * perfectly fine even if it's not called */
#endif
void
libblake_init(void)
{
	static volatile int initialised = 0;
	static volatile atomic_flag spinlock = ATOMIC_FLAG_INIT;

	if (initialised)
		return;

	while (atomic_flag_test_and_set(&spinlock));

	if (!initialised) {
		/* libblake_internal_blake2b_compress_mm128_init(); */
		/* libblake_internal_blake2b_compress_mm256_init(); */
		initialised = 1;
	}

	atomic_flag_clear(&spinlock);
}
