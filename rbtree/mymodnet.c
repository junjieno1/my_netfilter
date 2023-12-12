#include "sockopt.h"
#include <linux/init.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/spinlock.h>

#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/inet.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/string.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/rbtree.h>

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

struct mapcheck {
    char opt[4];
    char ip[16];
};

struct mynode {
    struct rb_node node;
    char *str_ip;
};

struct rb_root mytree = RB_ROOT;
static void clear_list(void);
// 增加
int my_insert(struct rb_root *root, struct mynode *data)
{
  	struct rb_node **new = &(root->rb_node), *parent = NULL;

  	/* Figure out where to put new node */
  	while (*new) {
  		struct mynode *this = container_of(*new, struct mynode, node);
  		int result = strcmp(data->str_ip, this->str_ip);

		parent = *new;
  		if (result < 0)
  			new = &((*new)->rb_left);
  		else if (result > 0)
  			new = &((*new)->rb_right);
  		else
  			return 0;
  	}

  	/* Add new node and rebalance tree. */
  	rb_link_node(&data->node, parent, new);
  	rb_insert_color(&data->node, root);

	return 1;
}

// 删除
void my_free(struct mynode *node)
{
	if (node != NULL) {
		if (node->str_ip != NULL) {
			kfree(node->str_ip);
			node->str_ip = NULL;
		}
		kfree(node);
		node = NULL;
	}
}

// 查找
struct mynode * my_search(struct rb_root *root, char *string)
{
  	struct rb_node *node = root->rb_node;

  	while (node) {
  		struct mynode *data = container_of(node, struct mynode, node);
		int result;

		result = strcmp(string, data->str_ip);

		if (result < 0)
  			node = node->rb_left;
		else if (result > 0)
  			node = node->rb_right;
		else
  			return data;
	}
	return NULL;
}

// 修改




static int save_rule(char *str_ip, int opt)
{
    struct mynode *new_node;
    unsigned long flags;
    __be32 ip;
    if (in4_pton(str_ip, -1, (u8 *)&ip, -1, NULL)) {
        printk(KERN_INFO "IP address: %pI4\n", &ip);
    } else {
        printk(KERN_INFO "Invalid IP address\n");
        return -EFAULT;
    }
    //
    if (opt == ADD_RULE) {
        new_node = kmalloc(sizeof(*new_node), GFP_KERNEL);
        if (new_node) {
            new_node->str_ip = kstrdup(str_ip, GFP_KERNEL);
            spin_lock_irqsave(&my_lock, flags);
            my_insert(&mytree, new_node);
            spin_unlock_irqrestore(&my_lock, flags);
        }
    } else if (opt == DEL_RULE) {
        spin_lock_irqsave(&my_lock, flags);
        new_node = my_search(&mytree, str_ip);
        if (new_node) {
            rb_erase(&new_node->node, &mytree);
		    my_free(new_node);
        }
        spin_unlock_irqrestore(&my_lock, flags);
        }
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
    } else if (strcmp(buffer, "clearall")==0) {
        clear_list();
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

    check_buffer(buffer);
    
    return 0;
}

static int getsockopt_handler(struct sock *sk, int optval, 
                                void __user *user, int *len)
{
    
    unsigned int copy_len;
    unsigned long flags;
    struct rb_node *node;
    unsigned int count = 0;
    buffer[0] = '\0';

    copy_len = *len > BUFFER_LEN_MAX ? BUFFER_LEN_MAX : *len;
    switch (optval)
    {
    case SOCKOPT_GET_BUFFER:
        spin_lock_irqsave(&my_lock, flags);
        for (node = rb_first(&mytree); node; node = rb_next(node)) {
            printk("get = %s\n", rb_entry(node, struct mynode, node)->str_ip);
            count++;
        }
        spin_unlock_irqrestore(&my_lock, flags);
        snprintf(buffer, BUFFER_LEN_MAX, "%d", count);
        printk(KERN_INFO "copy_to_user buffer [%s]\n", buffer);

        if (copy_to_user(user, (void*)&buffer[0], copy_len) != 0)
        {
            printk(KERN_INFO "copy_to_user opt error\n");
            return -EFAULT;
        }
        break;
    
    default:
        printk(KERN_INFO "unrecognized getsockopt opt: %d\n", optval);
        return -EFAULT;
    }
    
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
        unsigned long flags;
        struct mynode *data;
        int is_drop = 0;

		sb = skb;

		iph = ip_hdr(sb);
		sip = ntohl(iph->saddr);
		
		sprintf(str, "%u.%u.%u.%u", IPADDRESS(sip));
        
        /* 改成查表 */
        spin_lock_irqsave(&my_lock, flags);
        data = my_search(&mytree, str);
        if (data) {
            is_drop = 1;
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

static void rbtree_postorder_for_each_safe(struct rb_root *root, void (*func)(struct rb_node *))
{
    struct rb_node *node = rb_first(root);
    struct rb_node *next;
    while (node) {
        next = rb_next(node);
        func(node);
        node = next;
    }
}

static void my_free_node(struct rb_node *node)
{
    struct mynode *data = container_of(node, struct mynode, node);
    rb_erase(node, &mytree);
    printk("exit free ip : %s\n", data->str_ip);
    my_free(data);
}


static void clear_list(void)
{
	rbtree_postorder_for_each_safe(&mytree, my_free_node);
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