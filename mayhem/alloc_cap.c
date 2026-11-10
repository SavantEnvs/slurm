/*
 * Model a host that refuses a single allocation of 1 GiB or more (pack.h MAX_MSG_SIZE: no RPC body is
 * larger). slurm's safe_xcalloc() handles that failure by rejecting the message, so an unpack count
 * from the wire must not reach libFuzzer's malloc limit or the kernel OOM killer first.
 */
#include <errno.h>
#include <stddef.h>

#define ALLOC_CAP ((size_t) 1 << 30)

void *__real_malloc(size_t size);
void *__real_calloc(size_t count, size_t size);
void *__real_realloc(void *ptr, size_t size);

void *__wrap_malloc(size_t size)
{
	if (size >= ALLOC_CAP) {
		errno = ENOMEM;
		return NULL;
	}
	return __real_malloc(size);
}

void *__wrap_calloc(size_t count, size_t size)
{
	size_t total;

	if (__builtin_mul_overflow(count, size, &total) || total >= ALLOC_CAP) {
		errno = ENOMEM;
		return NULL;
	}
	return __real_calloc(count, size);
}

void *__wrap_realloc(void *ptr, size_t size)
{
	if (size >= ALLOC_CAP) {
		errno = ENOMEM;
		return NULL;
	}
	return __real_realloc(ptr, size);
}
