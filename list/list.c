#include <linux/init.h>
#include <linux/module.h>
#include <linux/list.h>
#include <linux/slab.h>

struct my_node {
    int data;
    struct list_head list;
};

static LIST_HEAD(my_list);

static int __init my_module_init(void) {
    int i;
    for (i = 0; i < 20; i++) {
        struct my_node *new_node = kmalloc(sizeof(*new_node), GFP_KERNEL);
        if (new_node) {
            new_node->data = i;
            INIT_LIST_HEAD(&new_node->list);
            list_add_tail(&new_node->list, &my_list);
        }
    }
    return 0;
}

static void __exit my_module_exit(void) {
    struct my_node *cur_node, *next_node;
    list_for_each_entry_safe(cur_node, next_node, &my_list, list) {
        printk(KERN_INFO "Removing %d\n", cur_node->data);
        list_del(&cur_node->list);
        kfree(cur_node);
    }
}

module_init(my_module_init);
module_exit(my_module_exit);

MODULE_LICENSE("GPL");