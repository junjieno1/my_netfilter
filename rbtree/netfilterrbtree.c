#include "sockopt.h"
#include <linux/init.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/slab.h>
#include <linux/rbtree.h>
#include <linux/spinlock.h>

#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/inet.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/string.h>
#include <linux/kthread.h>
#include <linux/delay.h>

#define BUFFER_LEN_MAX 1024
#define IPADDRESS(addr) \
    ((unsigned char *)&addr)[3], \
    ((unsigned char *)&addr)[2], \
    ((unsigned char *)&addr)[1], \
    ((unsigned char *)&addr)[0]

#define ADD_RULE 1
#define DEL_RULE 2

static char buffer[BUFFER_LEN_MAX];

static struct task_struct *thread_filter;
static struct task_struct *thread_sockopt;
static struct nf_hook_ops *nf_blockipaddr_ops = NULL;

spinlock_t my_lock;
struct my_node {
    char *str_ip;
    struct rb_node node;
};

struct rb_root my_tree = RB_ROOT;

struct mapcheck {
    char opt[4];
    char ip[16];
};

static int save_rule(char *str_ip, int opt)
{
    struct my_node *new_node, *cur_node;
    struct rb_node **new, *parent = NULL;
    __be32 ip;
    unsigned long flags;
    int cmp_result;

    if (in4_pton(str_ip, -1, (u8 *)&ip, -1, NULL)) {
        printk(KERN_INFO "IP address: %pI4\n", &ip);
    } else {
        printk(KERN_INFO "Invalid IP address\n");
        return -EFAULT;
    }

    spin_lock_irqsave(&my_lock, flags);
    if (opt == ADD_RULE) {
        new_node = kmalloc(sizeof(*new_node), GFP_KERNEL);
        if (new_node) {
            new_node->str_ip = kstrdup(str_ip, GFP_KERNEL);
            new = &(my_tree.rb_node);
            while (*new) {
                cur_node = rb_entry(*new, struct my_node, node);
                cmp_result = strcmp(str_ip, cur_node->str_ip);
                parent = *new;
                if (cmp_result < 0) {
                    new = &((*new)->rb_left);
                } else if (cmp_result > 0) {
                    new = &((*new)->rb_right);
                } else {
                    spin_unlock_irqrestore(&my_lock, flags);
                    return 0;
                }
            }
            rb_link_node(&new_node->node, parent, new);
            rb_insert_color(&new_node->node, &my_tree);
        }
    } else if (opt == DEL_RULE) {
        struct rb_node *node;
        for (node = rb_first(&my_tree); node; node = rb_next(node)) {
            cur_node = rb_entry(node, struct my_node, node);
            if (strcmp(str_ip, cur_node->str_ip) == 0) {
                rb_erase(node, &my_tree);
                kfree(cur_node->str_ip);
                kfree(cur_node);
            }
        }
    }
    spin_unlock_irqrestore(&my_lock, flags);
    return 0;
}

static int check_buffer(char *buffer)
{   
    int ret = 0;
    struct mapcheck mip = {0}; 
    memcpy((char*)&mip, buffer, strlen(buffer));
    mip.opt[3] = '\0';
    printk(KERN_INFO "opt :%s\n", mip.opt);
    printk(KERN_INFO "ip  :%s\n", mip.ip);

    if (strcmp(mip.opt, "add") == 0) {
        save_rule(mip.ip, ADD_RULE);
    } else if (strcmp(mip.opt, "del") == 0) {
        save_rule(mip.ip, DEL_RULE);
    }

    return ret;
}

static int setsockopt_handler(struct sock *sk, int optval, 
                                void __user *user, unsigned int len)
{
    switch (optval)
    {
        case SOCKOPT_SET_BUFFER:
            if (copy_from_user((void*)&buffer, user, len) != 0) {
                return -EFAULT;
            }
            break;
        default:
            printk(KERN_INFO "invalid setsockopt opt: %d\n", optval);
            return -EFAULT;
    }
    printk(KERN_INFO "get buffer : %s\n", buffer);

    //save_rule(buffer);
    check_buffer(buffer);
    
    return 0;
}

static int getsockopt_handler(struct sock *sk, int optval, 
                                void __user *user, int *len)
{
    unsigned int copy_len;
    struct rb_node *node;
    struct my_node *cur_node;
    unsigned long flags;
   
    copy_len = *len > BUFFER_LEN_MAX ? BUFFER_LEN_MAX : *len;
    switch (optval)
    {
    case SOCKOPT_GET_BUFFER:
        if (copy_to_user(user, (void*)&buffer[0], copy_len) != 0)
        {
            printk(KERN_INFO "getsockopt opt error\n");
            return -EFAULT;
        }
        break;
    
    default:
        printk(KERN_INFO "unrecognized getsockopt opt: %d\n", optval);
        return -EFAULT;
    }

    // 遍历
    spin_lock_irqsave(&my_lock, flags);
    for (node = rb_first(&my_tree); node; node = rb_next(node)) {
        cur_node = rb_entry(node, struct my_node, node);
        printk(KERN_INFO "getsockopt strip : %s\n", cur_node->str_ip);
    }
    spin_unlock_irqrestore(&my_lock, flags);
   
    return 0;
}

static struct nf_sockopt_ops sockopt_ops = {
    .pf = PF_INET,
    .set_optmin = SOCKOPT_SET_MIN,
    .set_optmax = SOCKOPT_SET_MAX,
    .set = setsockopt_handler,
    .get_optmin = SOCKOPT_GET_MIN,
    .get_optmax = SOCKOPT_GET_MAX,
    .get = getsockopt_handler,
};


static unsigned int nf_blockipaddr_handler(void *priv, struct sk_buff *skb, 
                                            const struct nf_hook_state *state)
{
    if (!skb) {
        return NF_ACCEPT;
    } else {
        char *str = (char *)kmalloc(16, GFP_KERNEL);
        u32 sip;
        struct sk_buff *sb = NULL;
        struct iphdr *iph;
        
        struct my_node *cur_node;
        struct rb_node *node;
        int is_drop = 0;
        unsigned long flags;

        sb = skb;
        iph = ip_hdr(sb);
        sip = ntohl(iph->saddr);
        sprintf(str, "%u.%u.%u.%u", IPADDRESS(sip));

        spin_lock_irqsave(&my_lock, flags);
        for (node = rb_first(&my_tree); node; node = rb_next(node)) {
            cur_node = rb_entry(node, struct my_node, node);
            if (!strcmp(str, cur_node->str_ip)) {
                printk(KERN_INFO "ip %s\n", str);
                is_drop = 1;
            }
        }
        spin_unlock_irqrestore(&my_lock, flags);

        if (is_drop) {
            return NF_DROP;
        } else {
            return NF_ACCEPT;
        }
    }
}

static int filter_func(void *data)
{
    nf_blockipaddr_ops = (struct nf_hook_ops*)kcalloc(1, sizeof(struct nf_hook_ops), GFP_KERNEL);
	if (nf_blockipaddr_ops != NULL) {
		nf_blockipaddr_ops->hook = (nf_hookfn*)nf_blockipaddr_handler;
		nf_blockipaddr_ops->hooknum = NF_INET_PRE_ROUTING;
		nf_blockipaddr_ops->pf = NFPROTO_IPV4;
		nf_blockipaddr_ops->priority = NF_IP_PRI_FIRST + 1;

		nf_register_net_hook(&init_net, nf_blockipaddr_ops);
	}
    printk(KERN_INFO "register filter_func success!\n");
    return 0;
}

static int sockopt_func(void *data)
{
    int ret = nf_register_sockopt(&sockopt_ops);
    if (ret !=0) {
        printk(KERN_INFO "register sockopt error!\n");
    } else {
        printk(KERN_INFO "register sockopt success!\n");
    }
    return ret;
}

static void exit_filter(void)
{
    if (thread_filter) {
        if (nf_blockipaddr_ops != NULL) {
            nf_unregister_net_hook(&init_net, nf_blockipaddr_ops);
            kfree(nf_blockipaddr_ops);
        }
    }
    printk(KERN_INFO "unregister net success!\n");
}

static void exit_sockopt(void)
{
    nf_unregister_sockopt(&sockopt_ops);
    printk(KERN_INFO "unregister sockopt success!\n");
}


static void clear_list(void)
{
    struct my_node *cur_node;
    struct rb_node *node;
    unsigned long flags;
    spin_lock_irqsave(&my_lock, flags);
    for (node = rb_first(&my_tree); node; node = rb_next(node)) {
        cur_node = rb_entry(node, struct my_node, node);
        printk(KERN_INFO "Clearing node with IP: %s\n", cur_node->str_ip);
        rb_erase(node, &my_tree);
        kfree(cur_node->str_ip);
        kfree(cur_node);
    }
    spin_unlock_irqrestore(&my_lock, flags);
    printk(KERN_INFO "clear_list success\n");
}

static int __init my_init(void)
{
    thread_filter = kthread_run(filter_func, NULL, "filter_func");
    if (IS_ERR(thread_filter)) {
        printk(KERN_INFO "create thread_filter failed!\n");
		return PTR_ERR(thread_filter);
    }

    thread_sockopt = kthread_run(sockopt_func, NULL, "sockopt_func");
    if (IS_ERR(thread_sockopt)) {
        printk(KERN_INFO "create thread_sockopt failed!\n");
		return PTR_ERR(thread_sockopt);
    }

    return 0;
}


static void __exit my_exit(void)
{
    exit_filter();
    exit_sockopt();
    clear_list();
    printk(KERN_INFO "EXIT\n");
}


module_init(my_init);
module_exit(my_exit);

MODULE_LICENSE("GPL");