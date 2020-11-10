/*
 *	xt_cookies - Xtables module to match cookies delivered by IPIP encapsulation
 *	Copyright © Yu Liu, 2020
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License; either
 *	version 2 of the License, or any later version, as published by the
 *	Free Software Foundation.
 */
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/netfilter/x_tables.h>
#include <linux/kernel.h>
#include <linux/inet.h>
#include <linux/export.h>
#include <linux/slab.h> // kmalloc
#include <linux/string.h>
#include <net/ip.h>
#include "compat_xtables.h"
#include <linux/string.h>
//#include <linux/kmod.h>

// Crypto related

#include <crypto/hash.h>
#include <crypto/skcipher.h>
#include <linux/crypto.h>

// My header
#include "xt_cookies.h"

#define MESSAGE_SIZE    1024
#define LOCAL_PORT      7744

// ***********************
//      Crypto functions
// ***********************

struct sdesc {
    struct shash_desc shash;
    char ctx[];
};

static struct sdesc *init_sdesc(struct crypto_shash *alg)
{
    struct sdesc *sdesc;
    int size;

    size = sizeof(struct shash_desc) + crypto_shash_descsize(alg);
    sdesc = kmalloc(size, GFP_KERNEL);
    if (!sdesc)
        return ERR_PTR(-ENOMEM);
    sdesc->shash.tfm = alg;
    sdesc->shash.flags = 0x0;
    return sdesc;
}

static int calc_hash(struct crypto_shash *alg,
             const unsigned char *data, unsigned int datalen,
             unsigned char *digest)
{
    struct sdesc *sdesc;
    int ret;

    sdesc = init_sdesc(alg);
    if (IS_ERR(sdesc)) {
        pr_info("can't alloc sdesc\n");
        return PTR_ERR(sdesc);
    }

    ret = crypto_shash_digest(&sdesc->shash, data, datalen, digest);
    kfree(sdesc);
    return ret;
}

static int test_hash(const unsigned char *data, unsigned int datalen,
             unsigned char *digest)
{
    struct crypto_shash *alg;
    char *hash_alg_name = "sha224";
    int ret;

    alg = crypto_alloc_shash(hash_alg_name, 0, 0);
    if (IS_ERR(alg)) {
            pr_info("can't alloc alg %s\n", hash_alg_name);
            return PTR_ERR(alg);
    }
    ret = calc_hash(alg, data, datalen, digest);
    crypto_free_shash(alg);
    return ret;
}

static void print_hash(unsigned char *digest) {
    unsigned char* dst = (unsigned char*)kzalloc(sizeof(unsigned char *) * 56, GFP_KERNEL);

    bin2hex(dst, digest, 28);

    printk(KERN_DEBUG "SHA224 in hex: %s", dst);
    kfree(dst);
}

char* get_IP(uint32_t ip) {
    unsigned char bytes[4];
    char *addr = (char*)kmalloc(sizeof(char) * 15, GFP_KERNEL);

    bytes[0] = ip & 0xFF;
    bytes[1] = (ip >> 8) & 0xFF;
    bytes[2] = (ip >> 16) & 0xFF;
    bytes[3] = (ip >> 24) & 0xFF;
    sprintf(addr, "%d.%d.%d.%d", bytes[0], bytes[1], bytes[2], bytes[3]);

    return addr;
}

bool verify_cookies(unsigned char* uid, unsigned char* nonce1, unsigned char* nonce2, unsigned char* sha224) {

    // Extract secret key from memory from memory based on cookies
    char *clientKey = (char *)kzalloc(CLIENT_KEY_LENGTH, GFP_KERNEL); // in binary
    char *clientKeyHexdump = (char *)kzalloc(CLIENT_KEY_LENGTH * 2, GFP_KERNEL);
    char *inputForClientKey = (char *)kzalloc(sizeof(char) * 10, GFP_KERNEL); // uid + nonce1 + serverKey = 5 + 2 + 2 + 3 = 10
	char *input = (char *)kzalloc(sizeof(char) * 65, GFP_KERNEL); // uid + nonce2 + clientKey = 5 + 2 + 56 = 63
	char *digest = (char *)kzalloc(sizeof(char) * 28, GFP_KERNEL); // SHA224 outputs 28 bytes
    
    unsigned char* r1;
    unsigned char* r2;

    printk(KERN_DEBUG "In verify_cookies function");
    
    // Calculate clientKey
    memcpy(inputForClientKey, uid, ID_LENGTH); // 5
    memcpy(inputForClientKey + ID_LENGTH, nonce1, NONCE_LENGTH); // 2
    memcpy(inputForClientKey + ID_LENGTH + NONCE_LENGTH, SERVER_KEY, SERVER_KEY_LENGTH); // 3
    
    test_hash(inputForClientKey, strlen(inputForClientKey), clientKey);
            
    bin2hex(clientKeyHexdump, clientKey, 28);
//    printk(KERN_DEBUG "Match module: clientKey in hex is: %s\n", clientKeyHexdump);
    
            memcpy(input, uid, ID_LENGTH); // UID: 5
    memcpy(input + ID_LENGTH, nonce2, NONCE_LENGTH); // Nonce2 : 2
    memcpy(input + ID_LENGTH + NONCE_LENGTH, clientKeyHexdump, CLIENT_KEY_LENGTH * 2); // 56

//    printk(KERN_DEBUG "Input: %s", input);
//    printk(KERN_DEBUG "strlen(input): %zu", strlen(input));
    
	test_hash(input, strlen(input), digest);
    
    r1 = (unsigned char*) kzalloc(56, GFP_KERNEL);
    bin2hex(r1, digest, 28);
//    printk(KERN_DEBUG "digest: %s", r1);
    
    r2 = (unsigned char*) kzalloc(56, GFP_KERNEL);
    bin2hex(r2, sha224, 28);
//    printk(KERN_DEBUG "sha224: %s", r2);
    
    kfree(r1);
    kfree(r2);
        
	// Check the length of digest
	if (strlen(digest) != 28) {
		printk(KERN_DEBUG "Length of digest is incorrect");
        kfree(clientKey);
        kfree(clientKeyHexdump);
        kfree(inputForClientKey);
        kfree(input);
        kfree(digest);
		return false;
	}

    printk(KERN_DEBUG "printing hash digest: \n");
    print_hash(digest);

	// Compare the digest
	if (strcmp(sha224, digest) == 0 ) {
		printk(KERN_DEBUG "Cookies verified, the flow should be allowed\n");
        kfree(clientKey);
        kfree(clientKeyHexdump);
        kfree(inputForClientKey);
        kfree(input);
        kfree(digest);

		return true;
	}
	else {
		printk(KERN_DEBUG "Cookies verification failed\n");
		printk(KERN_DEBUG "SHA224 in cookies: %s!\n", sha224);

        kfree(clientKey);
        kfree(clientKeyHexdump);
        kfree(inputForClientKey);
        kfree(input);
        kfree(digest);

		return false;
	}  
}

bool support_indication(struct iphdr* inner_ip_hdr) {
    // header length is 4 * 6 = 24
    if (inner_ip_hdr->ihl != 6) {
        printk(KERN_DEBUG "Cookies-support: the header length is not 24, return");
        return false;
    }
        
    char* command = (char*) kzalloc(1, GFP_KERNEL);
    memcpy(command, (unsigned char*)inner_ip_hdr + 22, 1);
    
    if (strcmp(command, "3") != 0) {
        kfree(command);
        return false;
    }
    kfree(command);
    return true;
}

static bool cookies_mt(const struct sk_buff *skb,
    struct xt_action_param *par)
{
    /* What to match?
            1. IP-in-IP protocol specified in the outer IP header
            2. Use our protocol, specified in inner IP header, with the proper type code
    */
    struct iphdr* iph = ip_hdr(skb);
    struct iphdr* inner_ip_hdr;
    unsigned char* str_inner_ip_hdr;
    
    char* dst10;
    unsigned char* uid = (unsigned char*) kzalloc(5, GFP_KERNEL);
    unsigned char* nonce1 = (unsigned char*) kzalloc(2, GFP_KERNEL);
    unsigned char* nonce2 = (unsigned char*) kzalloc(2, GFP_KERNEL);
    unsigned char* sha224 = (unsigned char*) kzalloc(28, GFP_KERNEL);
    unsigned char* cookie = (unsigned char*) kzalloc(37, GFP_KERNEL);
    
    // IP protocol needs to be IPIP
    if (iph->protocol != IPPROTO_IPIP) {
        printk(KERN_DEBUG "Not IPIP, return\n");
        printk(KERN_DEBUG "Protocol: %d", iph->protocol);
        return false;
    }
    
    inner_ip_hdr = ipip_hdr(skb);
    str_inner_ip_hdr = (unsigned char*) inner_ip_hdr;
    
    // Check if the packet is for support indication
    if (support_indication(inner_ip_hdr)) {
        printk(KERN_DEBUG "Cookies: received a packet indicates client support our protocol!");
        return true;
    }
    else {
        printk(KERN_DEBUG "Not support indication packet");
    }
    
    // The inner header should be 60 bytes
    if (inner_ip_hdr->ihl * 4 != 60) {
        printk(KERN_DEBUG "Not the IP header we looking for, return\n");
        return false;
    }

//    printk(KERN_DEBUG "Cookies: extracing the innerIP header to cookies struct\n");
    
    memcpy(uid, str_inner_ip_hdr + 20 + 3, ID_LENGTH);
    memcpy(nonce1, str_inner_ip_hdr + 20 + 3 + ID_LENGTH, NONCE_LENGTH);
    memcpy(nonce2, str_inner_ip_hdr + 20 + 3 + ID_LENGTH + NONCE_LENGTH, NONCE_LENGTH);
    memcpy(sha224, str_inner_ip_hdr + 20 + 3 + ID_LENGTH + NONCE_LENGTH * 2, SHA224_LENGTH);

    dst10 = (char*)kzalloc(56, GFP_KERNEL);
    bin2hex(dst10, sha224, 28);

    printk(KERN_DEBUG "uid: %s\n", (char *)uid);
    printk(KERN_DEBUG "nonce1: %s\n", (char *)nonce1);
    printk(KERN_DEBUG "nonce2: %s\n", (char *)nonce2);
    printk(KERN_DEBUG "sha224: %s\n", dst10);

    kfree(dst10);
    
    memcpy(cookie, uid, ID_LENGTH);
    memcpy(cookie + ID_LENGTH, nonce1, NONCE_LENGTH);
    memcpy(cookie + ID_LENGTH + NONCE_LENGTH, nonce2, NONCE_LENGTH);
    memcpy(cookie + ID_LENGTH + NONCE_LENGTH * 2, sha224, SHA224_LENGTH);

    printk(KERN_DEBUG "Verifying the cookie\n");
    
    // Verify the cookies
    
    if (!verify_cookies(uid, nonce1, nonce2, sha224)) {
        printk(KERN_DEBUG "Match module: Cookie verification failed\n");
        return false;
    }

    printk(KERN_DEBUG "Cookie is valid, return True\n");
        
    kfree(uid);
    kfree(nonce1);
    kfree(nonce2);
    kfree(sha224);
    return true;
}

static struct xt_match cookies_mt_reg __read_mostly = {
	.name      = "cookies",
	.revision  = 1,
	.family    = NFPROTO_IPV4,
	.match     = cookies_mt,
	.matchsize = sizeof(struct xt_cookies_mtinfo1),
	.me        = THIS_MODULE,
};

static int __init cookies_mt_init(void)
{
    printk(KERN_DEBUG "Match module: Cookies match is registered\n");
    return xt_register_match(&cookies_mt_reg);
}

static void __exit cookies_mt_exit(void)
{
    printk(KERN_DEBUG "Unload cookies module, save the IDs and cookies into file\n");
	xt_unregister_match(&cookies_mt_reg);
}

MODULE_DESCRIPTION("The one I developed");
MODULE_AUTHOR("Yu Liu");
MODULE_LICENSE("GPL");
MODULE_ALIAS("ipt_cookies");
module_init(cookies_mt_init);
module_exit(cookies_mt_exit);
