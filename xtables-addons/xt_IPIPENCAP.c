#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter/x_tables.h>
#include <linux/skbuff.h>
#include <linux/byteorder/generic.h>
#include <net/checksum.h>
#include <net/ip.h>
#include <linux/slab.h> // kmalloc
#include <linux/string.h>

#include "xt_IPIPENCAP.h"

// Crypto
#include <crypto/hash.h>
#include <crypto/skcipher.h>
#include <linux/crypto.h>


#ifdef DEBUG
static void print_skb_header_offsets(struct sk_buff *skb) {
	printk("Transport header offset: %u\n", skb->transport_header);
	printk("Network header offset: %u\n", skb->network_header);
	printk("MAC header offset: %u\n", skb->mac_header);
}
#endif

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

char* get_IP(uint32_t ip) {
    unsigned char bytes[4];
    char *addr = (char*)kzalloc(sizeof(char) * 15, GFP_KERNEL);

    bytes[0] = ip & 0xFF;
    bytes[1] = (ip >> 8) & 0xFF;
    bytes[2] = (ip >> 16) & 0xFF;
    bytes[3] = (ip >> 24) & 0xFF;
    sprintf(addr, "%d.%d.%d.%d", bytes[0], bytes[1], bytes[2], bytes[3]);

    return addr;
}

void generateClientKey(unsigned char* clientKey) {
    
    unsigned char* command = clientKey;
    unsigned char* uid = clientKey + 1; // 5 bytes
    unsigned char* nonce1 = clientKey + 6; // 2 bytes
    unsigned char* digest = clientKey + 8; // 28 bytes
    unsigned char* padding = clientKey + 36; // 2 bytes
    
    unsigned char* input = (unsigned char*) kzalloc(10, GFP_KERNEL);
    unsigned char* hex = (unsigned char*) kzalloc(56, GFP_KERNEL);

    
    // One can replace any random user id and nonce below.
    memcpy(command, "2", 1);
    memcpy(uid, "12345", 5);
    memcpy(nonce1, "12", 2);
    memset(padding, 0, 2); // 2 bytes padding
    
    memcpy(input, uid, 5); // 5
    memcpy(input + 5, nonce1, 2); // 2
    memcpy(input + 7, SERVER_KEY, SERVER_KEY_LENGTH); // 3
    
    test_hash(input, 10, digest);
    bin2hex(hex, digest, 28);
//    printk(KERN_DEBUG "IPIPENCAP: uid: %s", uid);
//    printk(KERN_DEBUG "IPIPENCAP: nonce1: %s", nonce1);
//    printk(KERN_DEBUG "IPIPENCAP: hexDump: %s", hex);
    kfree(hex);
    kfree(input);
    
        
    printk(KERN_DEBUG "IPIPENCAP: clientKey generated!");
}

static unsigned int ipipencap_tg(struct sk_buff *skb,
	const struct xt_action_param *par) {

    int ORIGINAL_IP_HEADER_LENGTH;
    int ORIGINAL_IP_TOTAL_LENGTH;
    int TRANSPORT_LENGTH;
    struct iphdr* iphdr_backup;
    unsigned char* tcp_backup;
    
    struct iphdr* original_iphdr;
    struct iphdr* outer_iphdr;
    struct iphdr* inner_iphdr;
    struct iphdr* ipiphdr;
    struct tcphdr* thdr;
    
    unsigned char* transport_data;
    int original_IP_length;
    
    uint8_t* types;
    uint8_t* length;
    unsigned char* clientKey;
    unsigned char* hexdump;
    unsigned char* added_data;
    
    __wsum csum32;

    original_iphdr = ip_hdr(skb);
    
    if (original_iphdr->protocol != IPPROTO_TCP) {
        printk(KERN_DEBUG "IPIPENCAP: correct src and dst, but not TCP packet, return");
        return XT_CONTINUE;
    }

    ORIGINAL_IP_HEADER_LENGTH = original_iphdr->ihl * 4;
    ORIGINAL_IP_TOTAL_LENGTH = ntohs(original_iphdr->tot_len);
    TRANSPORT_LENGTH = ORIGINAL_IP_TOTAL_LENGTH - ORIGINAL_IP_HEADER_LENGTH;
    
    // Add memory to end of the space
    added_data = skb_put(skb, INNER_IP_HEADER_LENGTH);
    memset(added_data, 0, INNER_IP_HEADER_LENGTH);
    memcpy(skb->data + 80, tcp_hdr(skb), TRANSPORT_LENGTH);
    
    // Start preparing to create a new IP header
    original_iphdr->protocol = IPPROTO_IPIP;
    original_iphdr->tot_len = htons(ntohs(original_iphdr->tot_len) + 60);
    inner_iphdr = (struct iphdr*) (skb->data + 20);
    
    memset(inner_iphdr, 1, INNER_IP_HEADER_LENGTH);
    memcpy(inner_iphdr, original_iphdr, ORIGINAL_IP_HEADER_LENGTH);
    inner_iphdr->protocol = IPPROTO_TCP;
    inner_iphdr->tot_len = htons(TRANSPORT_LENGTH + INNER_IP_HEADER_LENGTH);
    inner_iphdr->ihl += 10;
    inner_iphdr->daddr = original_iphdr->daddr;

    types = (uint8_t *) inner_iphdr + ORIGINAL_IP_HEADER_LENGTH;
    length = (uint8_t *) inner_iphdr + ORIGINAL_IP_HEADER_LENGTH + 1;
    clientKey = (unsigned char*) inner_iphdr + ORIGINAL_IP_HEADER_LENGTH + 2;
    
    // Set the inner IP options to indicate the support of our protocol
    (*types) = 222; // 0xde = 16 * 13 + 14 = 222, the value is pre-defined by our protocol, one can replace it with any other not conflicting values
    (*length) = 40; // Length of options, 40 bytes
    generateClientKey(clientKey); // 38 bytes

    thdr = (struct tcphdr*)(inner_iphdr + 60);
    csum32 = csum_partial(thdr, sizeof(struct tcphdr), 0);
    thdr->check = csum32;
    
    // Reset the checksum of innner IP header
    csum32 = csum_partial(inner_iphdr, sizeof(struct iphdr), 0);
    inner_iphdr->check = csum32;
    
    // Reset the checksum of outer IP header
    csum32 = csum_partial(original_iphdr, sizeof(struct iphdr), 0);
    original_iphdr->check = csum32;
        
//    printk(KERN_DEBUG "IPIPENCAP: after extension, bytes of paged data: %d", skb->data_len);
    
    return XT_CONTINUE;
}

static struct xt_target ipipencap_tg_reg __read_mostly = {
	.name		= "IPIPENCAP",
	.revision	= 0,
	.family		= NFPROTO_IPV4,
	.target		= ipipencap_tg,
	.table		= "mangle",
	.me			= THIS_MODULE,
};

static int __init ipipencap_tg_init(void) {
	printk(KERN_DEBUG "Targe module: IPIPENCAP is registered");
	return xt_register_target(&ipipencap_tg_reg);
}

static void __exit ipipencap_tg_exit(void) {
    printk(KERN_DEBUG "Targe module: IPIPENCAP is unloaded");
	return xt_unregister_target(&ipipencap_tg_reg);
}

module_init(ipipencap_tg_init);
module_exit(ipipencap_tg_exit);
MODULE_DESCRIPTION("Encapsulate IP-in-IP packet");
MODULE_AUTHOR("Yu Liu");
MODULE_LICENSE("GPL");
MODULE_ALIAS("ipt_IPIPDECAP");
