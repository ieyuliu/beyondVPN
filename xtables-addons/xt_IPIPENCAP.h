#ifndef _LINUX_NETFILTER_XT_IPIPDECAP_H
#define _LINUX_NETFILTER_XT_IPIPDECAP_H	1

#define XT_IPOPTSTRIP_IS_SET(flags,flag) flags & flag


enum {
	XT_IPIPDECAP_KEEP_DST = 0x01,
};

struct xt_ipipdecap_tg_info {
	__u8 flags;
};

#define IPV4_HL 5
#define IPV4_LEN 20

#define INNER_IP_HEADER_LENGTH  60
#define SHA224_LENGTH           28 // Bytes
#define SERVER_KEY              "mew"
#define SERVER_KEY_LENGTH       3
#define CLIENT_KEY_LENGTH       29 // uid + nonce1 + SHA224 + padding = 1 + 5 + 2 + 28 + 2= 38
#define OPTION_LENGTH           40 // bytes
#define NONCE_LENGTH            2 // bytes


#endif 
