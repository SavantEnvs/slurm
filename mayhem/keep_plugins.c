/*
 * slurm's plugin_peek() dlopen()s and dlclose()s every plugin while scanning plugindir. libFuzzer keeps
 * the unloaded plugin's SanCov counter range registered and then memsets unmapped memory every
 * iteration, so keep dlopen'ed plugins resident.
 */
int dlclose(void *handle)
{
	(void) handle;
	return 0;
}
