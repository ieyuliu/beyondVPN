#ifndef _LINUX_NETFILTER_XT_IPIPDECAP_H
#define _LINUX_NETFILTER_XT_IPIPDECAP_H	1

#define XT_IPOPTSTRIP_IS_SET(flags,flag) flags & flag


enum {
	XT_IPIPDECAP_KEEP_DST = 0x01,
};

#define IPV4_HL 5
#define IPV4_LEN 20

struct xt_ipipdecap_tg_info {
	__u8 flags;
};

#endif 
