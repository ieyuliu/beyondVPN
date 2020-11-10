#include <stdio.h>
#include <xtables.h>
#include <getopt.h>
//#include "xt_IPIPDECAP.h"



/* Display help text */
static void ipipdecap_tg_help(void) {
	printf("IPIPDECAP takes no options\n\n");
}

/* Parse options */
static int ipipdecap_tg_parse(int c, char **argv, int invert,
	unsigned int *flags, const void *entry, struct xt_entry_target **targetinfo) {
	return 0;
}

static void ipipdecap_tg_check(unsigned int flags) {

}

static struct xtables_target ipipdecap_tg_reg = {
	.version		= XTABLES_VERSION,
	.name			= "IPIPDECAP",
	.revision		= 0,
	.family			= NFPROTO_IPV4,
	.parse			= ipipdecap_tg_parse,
	.help			= ipipdecap_tg_help,
	.final_check		= ipipdecap_tg_check
};

void _init(void) {
	xtables_register_target(&ipipdecap_tg_reg);
}
