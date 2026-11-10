/*
 * Bitstring text codecs: bit_unfmt() ("0-3,8,10-12"), bit_unfmt_hexmask() and
 * their formatters, over a bitstring sized from the first two input bytes.
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "slurm/slurm.h"
#include "src/common/bitstring.h"
#include "src/common/log.h"
#include "src/common/xmalloc.h"

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	log_options_t opts = LOG_OPTS_INITIALIZER;

	opts.stderr_level = LOG_LEVEL_QUIET;

	log_init("fuzz_bitstring", opts, 0, NULL);
	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	bitstr_t *b, *c;
	char *str, *s;
	int nbits;

	if (size < 3)
		return -1;
	nbits = 1 + (((data[0] << 8) | data[1]) % 4096);
	str = xmalloc(size - 1);
	memcpy(str, data + 2, size - 2);

	b = bit_alloc(nbits);
	if ((data[2] & 1) ? bit_unfmt(b, str) : bit_unfmt_hexmask(b, str)) {
		bit_free(b);
		xfree(str);
		return -1;
	}

	s = bit_fmt_full(b);
	xfree(s);
	s = bit_fmt_hexmask(b);
	xfree(s);
	s = bit_fmt_hexmask_trim(b);
	xfree(s);
	s = bit_fmt_range(b, 0, nbits);
	xfree(s);

	c = bit_copy(b);
	bit_set_count(c);
	bit_super_set(b, c);
	bit_pick_firstn(c, data[2] % 8);
	bit_free(c);
	c = bit_pick_cnt(b, bit_set_count(b) / 2);
	bit_free(c);

	bit_free(b);
	xfree(str);
	return 0;
}
