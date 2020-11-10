#ifndef _LINUX_NETFILTER_XT_IPV4OPTIONS_H
#define _LINUX_NETFILTER_XT_IPV4OPTIONS_H 1

#define COOKIE_LENGTH           37      // Bytes
#define ID_LENGTH               5       // Bytes
#define NONCE_LENGTH		    2		// Bytes
#define INNER_IP_HEADER_LENGTH  60      // Bytes
#define SHA224_LENGTH           28      // Bytes
#define SERVER_KEY		"mew" // Replace with any random server_key
#define SERVER_KEY_LENGTH	3
#define CLIENT_KEY_LENGTH	28 // SHA224	

/* IPv4 allows for a 5-bit option number - 32 options */

enum xt_cookies_flags {
    XT_USER_ID           = 1 << 0,
    XT_USER_ID_INV       = 1 << 1,
};

/**
 * @map:	bitmask of options that should appear
 * @invert:	inversion map
 * @flags:	see above
 */
struct xt_cookies_mtinfo1 {
    char user_id[3];
};

struct xt_cookies {
    char* uid;
    char* nonce;
    char* sha224;
};

struct xt_cookies_account_info {
        struct xt_cookies_account_info *left, *right;
        char *user_id;
        char *secret_key;
};

#endif /* _LINUX_NETFILTER_XT_IPV4OPTIONS_H */
