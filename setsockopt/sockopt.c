#include "sockopt.h"
#include <linux/init.h>
#include <linux/module.h>
#include <linux/netfilter.h>

#define BUFFER_LEN_MAX 1024
static char buffer[BUFFER_LEN_MAX];

static int setsockopt_handler(struct sock *sk, int optval, void __user *user, unsigned int len)
{
    switch(optval)
    {
        case SOCKOPT_SET_BUFFER:
            if (copy_from_user((void*)&buffer, user, len) != 0)
            {
                return -EFAULT;
            }
            break;
        default:
            printk("invalid setsockopt opt: %d\n", optval);
            return -EFAULT;
    }

    printk("setsockopt opt, buffer: [%s]\n", buffer);
    return 0;
}

static int getsockopt_handler(struct sock *sk, int optval, void __user *user, int *len)
{
    unsigned int copy_len;
    copy_len = *len > BUFFER_LEN_MAX ? BUFFER_LEN_MAX : *len;
    switch (optval)
    {
    case SOCKOPT_GET_BUFFER:
        if (copy_to_user(user, (void*)&buffer[0], copy_len) != 0)
        {
            printk("getsockopt opt error\n");
            return -EFAULT;
        }
        break;
    
    default:
        printk("unrecognized getsockopt opt: %d\n", optval);
        return -EFAULT;
    }

    return 0;

}

static struct nf_sockopt_ops sockopt_test_ops = {
    .pf = PF_INET,
    .set_optmin = SOCKOPT_SET_MIN,
    .set_optmax = SOCKOPT_SET_MAX,
    .set = setsockopt_handler,
    .get_optmin = SOCKOPT_GET_MIN,
    .get_optmax = SOCKOPT_GET_MAX,
    .get = getsockopt_handler,
};

static int __init sockopt_init(void)
{
    int result = 0;
    result = nf_register_sockopt(&sockopt_test_ops);
    if (result != 0) {
        printk("register sockopt error!\n");
    } else {
        printk("register sockopt success!\n");
    }
    return result;
}

static void __exit sockopt_exit(void)
{
    nf_unregister_sockopt(&sockopt_test_ops);
    printk("unregister sockopt success!\n");
}


module_init(sockopt_init);
module_exit(sockopt_exit);

MODULE_DESCRIPTION("sockopt test");
MODULE_LICENSE("GPL");