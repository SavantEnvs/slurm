/*
 * slurmctld/slurmd/slurmd RPC message bodies: unpack_msg() over a message
 * type and protocol version taken from the first three input bytes.
 *
 * The daemons initialise the cred, hash, switch, gres and topology interfaces
 * before they unpack a message (unpack_msg() reaches slurm_cred_unpack(),
 * hash_g_compute(), switch_g_stepinfo_unpack(), gres_*_state_unpack() and
 * topology_g_*_unpack(), which assert or call through ops that are only set
 * by those init calls), so the harness does the same.
 */
#include <stdint.h>
#include <string.h>

#include "slurm/slurm.h"
#include "src/common/log.h"
#include "src/common/pack.h"
#include "src/common/read_config.h"
#include "src/common/slurm_protocol_common.h"
#include "src/common/slurm_protocol_defs.h"
#include "src/common/slurm_protocol_pack.h"
#include "src/common/xmalloc.h"
#include "src/common/xstring.h"
#include "src/interfaces/cred.h"
#include "src/interfaces/gres.h"
#include "src/interfaces/hash.h"
#include "src/interfaces/switch.h"
#include "src/interfaces/topology.h"

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

	log_init("fuzz_unpack_msg", opts, 0, NULL);
	slurm_conf.plugindir = xstrdup(MAYHEM_PLUGINDIR);
	slurm_conf.cred_type = xstrdup("cred/none");
	slurm_conf.topology_plugin = xstrdup("topology/flat");
	if (cred_g_init() || hash_g_init() || switch_g_init(true) ||
	    gres_init() || topology_g_init())
		abort();
	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	slurm_msg_t msg;
	buf_t *buf;
	char *body;
	size_t body_len;
	int rc;

	if (size < 3)
		return -1;
	body_len = size - 3;
	body = xmalloc(body_len ? body_len : 1);
	memcpy(body, data + 3, body_len);
	buf = create_buf(body, body_len);

	slurm_msg_t_init(&msg);
	msg.msg_type = (data[0] << 8) | data[1];
	msg.protocol_version = versions[data[2] % ARRAY_SIZE(versions)];

	rc = unpack_msg(&msg, buf);
	if (rc == SLURM_SUCCESS)
		slurm_free_msg_data(msg.msg_type, msg.data);
	free_buf(buf);
	return (rc == SLURM_SUCCESS) ? 0 : -1;
}
