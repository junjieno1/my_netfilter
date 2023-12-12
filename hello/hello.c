#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/string.h>
#include <linux/kthread.h>
#include <linux/delay.h>

#define IPADDRESS(addr) \
	((unsigned char *)&addr)[3], \
	((unsigned char *)&addr)[2], \
	((unsigned char *)&addr)[1], \
	((unsigned char *)&addr)[0]

static char *ip_addr_rule = "192.168.199.144";
static struct nf_hook_ops *nf_blockicmppkt_ops = NULL;
static struct nf_hook_ops *nf_blockipaddr_ops = NULL;

static struct task_struct *thread1;
static struct task_struct *thread2;
static unsigned long traffic_counter = 0;

static int speed(void *data)
{
	unsigned long prve_counter = 0;
	while (!kthread_should_stop()) {
        msleep(1000);
        printk(KERN_INFO "speed %lu Kb/sec\n", (traffic_counter - prve_counter)/1024);
		prve_counter = traffic_counter;
    }
    printk(KERN_INFO "Thread stopped\n");
    return 0;
}

static unsigned int nf_blockipaddr_handler(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
	if (!skb) {
		return NF_ACCEPT;
	} else {
		char *str = (char *)kmalloc(16, GFP_KERNEL);
		u32 sip;
		struct sk_buff *sb = NULL;
		struct iphdr *iph;

		sb = skb;
		traffic_counter += sb->len;

		iph = ip_hdr(sb);
		sip = ntohl(iph->saddr);
		
		sprintf(str, "%u.%u.%u.%u", IPADDRESS(sip));
		if(!strcmp(str, ip_addr_rule)) {
            printk(KERN_INFO "ip %s\n", str);
			return NF_DROP;
		} else {
			return NF_ACCEPT;
		}
	}
}


static unsigned int nf_blockicmppkt_handler(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
	struct iphdr *iph;
	struct udphdr *udph;
	if(!skb)
		return NF_ACCEPT;
	iph = ip_hdr(skb);
	if(iph->protocol == IPPROTO_UDP) {
		udph = udp_hdr(skb);
		if(ntohs(udph->dest) == 53) {
			return NF_ACCEPT;
		}
	}
	else if (iph->protocol == IPPROTO_TCP) {
		return NF_ACCEPT;
	}
	else if (iph->protocol == IPPROTO_ICMP) {
		printk(KERN_INFO "Drop ICMP packet \n");
		return NF_DROP;
	}
	return NF_ACCEPT;
}

static int myfilter(void *data)
{
	nf_blockicmppkt_ops = (struct nf_hook_ops*)kcalloc(1,  sizeof(struct nf_hook_ops), GFP_KERNEL);
	if (nf_blockicmppkt_ops != NULL) {
		nf_blockicmppkt_ops->hook = (nf_hookfn*)nf_blockicmppkt_handler;
		nf_blockicmppkt_ops->hooknum = NF_INET_PRE_ROUTING;
		nf_blockicmppkt_ops->pf = NFPROTO_IPV4;
		nf_blockicmppkt_ops->priority = NF_IP_PRI_FIRST;
		
		nf_register_net_hook(&init_net, nf_blockicmppkt_ops);
	}
	nf_blockipaddr_ops = (struct nf_hook_ops*)kcalloc(1, sizeof(struct nf_hook_ops), GFP_KERNEL);
	if (nf_blockipaddr_ops != NULL) {
		nf_blockipaddr_ops->hook = (nf_hookfn*)nf_blockipaddr_handler;
		nf_blockipaddr_ops->hooknum = NF_INET_PRE_ROUTING;
		nf_blockipaddr_ops->pf = NFPROTO_IPV4;
		nf_blockipaddr_ops->priority = NF_IP_PRI_FIRST + 1;

		nf_register_net_hook(&init_net, nf_blockipaddr_ops);
	}

	return 0;
}

static int __init nf_minifirewall_init(void) {
	
	printk(KERN_INFO "create kthread!\n");
	
	thread1 = kthread_run(speed,  NULL, "myspeed");
	if (IS_ERR(thread1)) {
		printk(KERN_INFO "create kthread failed!\n");
		return PTR_ERR(thread1);
	}
	printk(KERN_INFO "create kthread success!\n");


	thread2 = kthread_run(myfilter,  NULL, "myfilter");
	if (IS_ERR(thread2)) {
		printk(KERN_INFO "create kthread failed!\n");
		return PTR_ERR(thread2);
	}
	printk(KERN_INFO "create kthread success!\n");

	return 0;
}

static void __exit nf_minifirewall_exit(void) {
	if (thread1) {
	    kthread_stop(thread1);
	}
	printk(KERN_INFO "Cleaning up threads\n");
	
	
	if (thread2) {
		if(nf_blockicmppkt_ops != NULL) {
			nf_unregister_net_hook(&init_net, nf_blockicmppkt_ops);
			kfree(nf_blockicmppkt_ops);
		}
		if (nf_blockipaddr_ops  != NULL) {
			nf_unregister_net_hook(&init_net, nf_blockipaddr_ops);
			kfree(nf_blockipaddr_ops);
		}
	    kthread_stop(thread2);
	}
	printk(KERN_INFO "Exit");
}

module_init(nf_minifirewall_init);
module_exit(nf_minifirewall_exit);

MODULE_AUTHOR("jj");
MODULE_DESCRIPTION("icmp or ip=192.168.199.144");
MODULE_VERSION("100");
MODULE_LICENSE("GPL");
