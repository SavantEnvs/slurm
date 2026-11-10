/*
 * URL handling: the url_parser plugin (scheme://user@host:port/path?q#frag),
 * URL path splitting into data_t, and HTTP method / scheme name lookups.
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "slurm/slurm.h"
#include "src/common/data.h"
#include "src/common/http.h"
#include "src/common/log.h"
#include "src/common/pack.h"
#include "src/common/read_config.h"
#include "src/common/xmalloc.h"
#include "src/common/xstring.h"
#include "src/interfaces/url_parser.h"

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	log_options_t opts = LOG_OPTS_INITIALIZER;

	opts.stderr_level = LOG_LEVEL_QUIET;

	log_init("fuzz_url", opts, 0, NULL);
	slurm_conf.plugindir = xstrdup(MAYHEM_PLUGINDIR);
	if (url_parser_g_init())
		abort();
	return 0;
}

static int _on_entry(const char *entry, bool tmpl, void *arg)
{
	return SLURM_SUCCESS;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	uint8_t ops;
	char *str;
	size_t len;
	buf_t *buf;
	url_t url = URL_INITIALIZER;
	data_t *d;
	url_scheme_t scheme;

	if (size < 2)
		return -1;
	ops = data[0];
	str = xmalloc(size);
	memcpy(str, data + 1, size - 1);

	len = strlen(str);

	/* url_parser reads its length from the buffer offset (processed), as conmgr's callers set it */
	buf = create_buf(xstrdup(str), len);
	set_buf_offset(buf, len);
	if (!url_parser_g_parse("fuzz", buf, &url))
		url_free_members(&url);
	free_buf(buf);

	if (ops & 1) {
		d = parse_url_path(str, ops & 2, ops & 4);
		FREE_NULL_DATA(d);
	}
	if (ops & 8)
		url_path_walk(str, ops & 16, _on_entry, NULL);
	if (ops & 32) {
		get_http_method(str);
		get_http_status_code(str);
		url_get_scheme(str, len, &scheme);
	}

	xfree(str);
	return 0;
}
