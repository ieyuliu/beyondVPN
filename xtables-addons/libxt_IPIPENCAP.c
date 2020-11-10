#include <stdio.h>
#include <xtables.h>
#include <getopt.h>
//#include "xt_IPIPENCAP.h"

/* Display help text */
static void ipipencap_tg_help(void) {
	printf("IPIPENCAP takes no options\n\n");
}

/* Parse options */
static int ipipencap_tg_parse(int c, char **argv, int invert,
	unsigned int *flags, const void *entry, struct xt_entry_target **targetinfo) {

	return 0;
}

static void ipipencap_tg_check(unsigned int flags) {

}

static struct xtables_target ipipencap_tg_reg = {
	.version		= XTABLES_VERSION,
	.name			= "IPIPENCAP",
	.revision		= 0,
	.family			= NFPROTO_IPV4,
	.parse			= ipipencap_tg_parse,
	.help			= ipipencap_tg_help,
	.final_check		= ipipencap_tg_check
};

void _init(void) {
	xtables_register_target(&ipipencap_tg_reg);
}
