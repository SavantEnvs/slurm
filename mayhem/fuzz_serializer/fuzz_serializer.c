/*
 * JSON / YAML / url-encoded deserializer plugins into data_t trees, then
 * re-serialize the tree and run tree conversions on it.
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "slurm/slurm.h"
#include "src/common/data.h"
#include "src/common/log.h"
#include "src/common/read_config.h"
#include "src/common/xmalloc.h"
#include "src/common/xstring.h"
#include "src/interfaces/serializer.h"

static const char *mime_types[] = {
	MIME_TYPE_JSON,
	MIME_TYPE_YAML,
	"application/x-www-form-urlencoded",
};

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	log_options_t opts = LOG_OPTS_INITIALIZER;

	opts.stderr_level = LOG_LEVEL_QUIET;

	log_init("fuzz_serializer", opts, 0, NULL);
	slurm_conf.plugindir = xstrdup(MAYHEM_PLUGINDIR);
	if (serializer_g_init())
		abort();
	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	const char *mime;
	data_t *d = NULL, *copy;
	char *src, *out = NULL;
	size_t out_len = 0;

	if (size < 2)
		return -1;
	mime = mime_types[data[0] % ARRAY_SIZE(mime_types)];
	src = xmalloc(size);
	memcpy(src, data + 1, size - 1);

	if (serialize_g_string_to_data(&d, src, size - 1, mime)) {
		xfree(src);
		FREE_NULL_DATA(d);
		return -1;
	}

	copy = data_copy(NULL, d);
	data_convert_tree(copy, DATA_TYPE_NONE);
	FREE_NULL_DATA(copy);

	if (!serialize_g_data_to_string(&out, &out_len, d, MIME_TYPE_JSON,
					SER_FLAGS_COMPACT))
		xfree(out);
	out = NULL;
	if (!serialize_g_data_to_string(&out, &out_len, d, MIME_TYPE_YAML,
					SER_FLAGS_NONE))
		xfree(out);

	FREE_NULL_DATA(d);
	xfree(src);
	return 0;
}
