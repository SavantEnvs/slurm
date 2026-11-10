/*
 * Hostlist parser + operations: the bytes after a 1-byte op selector are a
 * hostlist expression ("n[001-010,15],gpu[1-3]") handed to hostlist_create().
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "slurm/slurm.h"
#include "src/common/hostlist.h"
#include "src/common/log.h"
#include "src/common/xmalloc.h"

#define MAX_WALK 64

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	log_options_t opts = LOG_OPTS_INITIALIZER;

	opts.stderr_level = LOG_LEVEL_QUIET;

	log_init("fuzz_hostlist", opts, 0, NULL);
	return 0;
}

static void _walk(hostlist_t *hl, int remove_every)
{
	hostlist_iterator_t *it = hostlist_iterator_create(hl);
	char *host;
	int n = 0;

	while (n < MAX_WALK && (host = hostlist_next(it))) {
		xfree(host);
		n++;
		if (remove_every && !(n % remove_every))
			hostlist_remove(it);
	}
	hostlist_iterator_reset(it);
	hostlist_iterator_destroy(it);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	uint8_t ops;
	char *str, *s;
	hostlist_t *hl, *hl2;
	hostset_t *set;

	if (size < 2)
		return -1;
	ops = data[0];
	str = xmalloc(size);
	memcpy(str, data + 1, size - 1);

	hl = hostlist_create(str);
	if (!hl) {
		xfree(str);
		return -1;
	}

	s = hostlist_ranged_string_xmalloc(hl);
	xfree(s);

	if (hostlist_count(hl) <= 4096) {
		s = hostlist_deranged_string_xmalloc(hl);
		xfree(s);
	}

	if (ops & 0x01)
		hostlist_sort(hl);
	if (ops & 0x02)
		hostlist_uniq(hl);
	if (ops & 0x04)
		_walk(hl, (ops >> 4) & 3);
	if (ops & 0x08) {
		hl2 = hostlist_copy(hl);
		hostlist_sort(hl2);
		hostlist_push_list(hl, hl2);
		hostlist_uniq(hl);
		hostlist_destroy(hl2);
	}
	if (ops & 0x10) {
		int cnt = hostlist_count(hl);
		if (cnt > 0) {
			s = hostlist_nth(hl, cnt / 2);
			if (s) {
				hostlist_find(hl, s);
				hostlist_delete_host(hl, s);
				xfree(s);
			}
			hostlist_delete_nth(hl, 0);
		}
	}
	if (ops & 0x20) {
		s = hostlist_shift(hl);
		xfree(s);
		s = hostlist_pop(hl);
		xfree(s);
		hostlist_push_host(hl, str);
	}
	if (ops & 0x40) {
		hostlist_t **parts = NULL;
		int n = 0;

		if (hostlist_split_treewidth(hl, &parts, &n, 1 + (size % 16)) ==
		    SLURM_SUCCESS) {
			for (int i = 0; i < n; i++)
				hostlist_destroy(parts[i]);
			xfree(parts);
		}
	}
	if (ops & 0x80) {
		set = hostset_create(str);
		if (set) {
			hostset_insert(set, str);
			hostset_within(set, str);
			hostset_intersects(set, str);
			hostset_delete(set, str);
			s = hostset_ranged_string_xmalloc(set);
			xfree(s);
			hostset_destroy(set);
		}
	}

	s = hostlist_ranged_string_xmalloc(hl);
	xfree(s);
	hostlist_destroy(hl);
	xfree(str);
	return 0;
}
