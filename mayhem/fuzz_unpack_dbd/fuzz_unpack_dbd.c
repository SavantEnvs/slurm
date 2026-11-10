/*
 * slurmdbd RPC message bodies: unpack_slurmdbd_msg() over a protocol version
 * taken from the first input byte; the message type is read from the buffer.
 */
#include <stdint.h>
#include <string.h>

#include "slurm/slurm.h"
#include "src/common/log.h"
#include "src/common/pack.h"
#include "src/common/slurm_protocol_common.h"
#include "src/common/slurmdbd_defs.h"
#include "src/common/slurmdbd_pack.h"
#include "src/common/xmalloc.h"

static const uint16_t versions[] = {
	SLURM_PROTOCOL_VERSION,
	SLURM_ONE_BACK_PROTOCOL_VERSION,
	SLURM_TWO_BACK_PROTOCOL_VERSION,
	SLURM_MIN_PROTOCOL_VERSION,
};

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	log_options_t opts = LOG_OPTS_INITIALIZER;

	opts.stderr_level = LOG_LEVEL_QUIET;

	log_init("fuzz_unpack_dbd", opts, 0, NULL);
	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	slurmdbd_msg_t msg;
	buf_t *buf;
	char *body;
	size_t body_len;
	int rc;

	if (size < 3)
		return -1;
	body_len = size - 1;
	body = xmalloc(body_len);
	memcpy(body, data + 1, body_len);
	buf = create_buf(body, body_len);

	memset(&msg, 0, sizeof(msg));
	rc = unpack_slurmdbd_msg(&msg, versions[data[0] % ARRAY_SIZE(versions)],
				 buf);
	if (rc == SLURM_SUCCESS)
		slurmdbd_free_msg(&msg);
	free_buf(buf);
	return (rc == SLURM_SUCCESS) ? 0 : -1;
}
