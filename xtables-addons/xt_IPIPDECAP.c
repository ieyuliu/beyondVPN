#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter/x_tables.h>
#include <linux/skbuff.h>
#include <linux/byteorder/generic.h>
#include <net/checksum.h>
#include <net/ip.h>

#include "xt_IPIPDECAP.h"


#ifdef DEBUG
static void print_skb_header_offsets(struct sk_buff *skb) {
	printk("Transport header offset: %u\n", skb->transport_header);
	printk("Network header offset: %u\n", skb->network_header);
	printk("MAC header offset: %u\n", skb->mac_header);
}
#endif

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

static unsigned int ipipdecap_tg(struct sk_buff *skb,
	const struct xt_action_param *par) {

    struct iphdr *outer_iphdr;
    struct iphdr *inner_iphdr;
    struct tcphdr* tcp_hdr;
    unsigned char* transport_header;
    int inner_iphdr_length;
    int ipip_total_length;
    __wsum csum32;

    outer_iphdr = ip_hdr(skb);

	// We only work on IP-in-IP packet
	if (outer_iphdr->protocol != IPPROTO_IPIP) {
		return XT_CONTINUE;
	}

    printk(KERN_DEBUG "IPIPDECAP: Found target IPIP packet!\n");

	inner_iphdr = ipip_hdr(skb);
	inner_iphdr_length = inner_iphdr->ihl * 4;
    ipip_total_length = ntohs(inner_iphdr->tot_len);
    printk(KERN_DEBUG "IPIPDECAP: Total length of inner IP header: %u\n",ipip_total_length);

    transport_header = skb_transport_header(skb);

    tcp_hdr = (struct tcphdr*) (transport_header + inner_iphdr_length);
    printk(KERN_DEBUG "IPIPDECAP: length of TCP header is: %d\n", tcp_hdr->doff * 4);

    // Modify related section in outer IP header
    outer_iphdr->tot_len = htons(ntohs(outer_iphdr->tot_len) - inner_iphdr_length);
    outer_iphdr->protocol = inner_iphdr->protocol;

    // Set the new header to skb buffer
    skb_set_transport_header(skb, outer_iphdr->ihl * 4);

    // Remove inner_ip_header,
    memmove(transport_header, transport_header + inner_iphdr_length, ipip_total_length - inner_iphdr_length);

    // Trim the saved space
    skb_trim(skb, (skb->len - inner_iphdr_length));
    printk(KERN_DEBUG "IPIPDECAP: inner_uphdr_length: %d", inner_iphdr_length);
    // Re-calculate IP header checksum
    csum32 = csum_partial(outer_iphdr, sizeof(struct iphdr), 0);
    outer_iphdr->check = csum_fold(csum32);

    printk(KERN_DEBUG "IPIPDECAP: IPIP decapsulated!!!\n");

    tcp_hdr = (struct tcphdr*) skb_transport_header(skb);
    printk(KERN_DEBUG "IPIPDECAP: Dest port: %d\n", htons((unsigned short int) tcp_hdr->dest));
    printk(KERN_DEBUG "IPIPDECAP: Set the mark to 1");
    skb->mark = 1;
    kfree(transport_header);

    printk(KERN_DEBUG "IPIPDECAP: continue the packet");
    return XT_CONTINUE;
}

static struct xt_target ipipdecap_tg_reg __read_mostly = {
	.name		= "IPIPDECAP",
	.revision	= 0,
	.family		= NFPROTO_IPV4,
	.target		= ipipdecap_tg,
	.table		= "mangle",
	.me			= THIS_MODULE,
};

static int __init ipipdecap_tg_init(void) {
	printk(KERN_DEBUG "Targe module: IPIPDECAP is registered");
	return xt_register_target(&ipipdecap_tg_reg);
}

static void __exit ipipdecap_tg_exit(void) {
    printk(KERN_DEBUG "Targe module: IPIPDECAP is unloaded");
	return xt_unregister_target(&ipipdecap_tg_reg);
}

module_init(ipipdecap_tg_init);
module_exit(ipipdecap_tg_exit);
MODULE_DESCRIPTION("Decapsulate IP-in-IP packet");
MODULE_AUTHOR("Yu Liu");
MODULE_LICENSE("GPL");
MODULE_ALIAS("ipt_IPIPDECAP");
