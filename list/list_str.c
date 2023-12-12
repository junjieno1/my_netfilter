#include <linux/init.h>
#include <linux/module.h>
#include <linux/list.h>
#include <linux/slab.h>

struct my_node {
    char *str;
    struct list_head list;
};

static LIST_HEAD(my_list);

static int __init my_module_init(void) {
    char *data[] = {"hello1", "hello2", "hello3"};
    int i;
    for (i = 0; i < 3; i++) {
        struct my_node *new_node = kmalloc(sizeof(*new_node), GFP_KERNEL);
        if (new_node) {
            new_node->str = kstrdup(data[i], GFP_KERNEL);
            INIT_LIST_HEAD(&new_node->list);
            list_add_tail(&new_node->list, &my_list);
        }
    }
    return 0;
}

static void __exit my_module_exit(void) {
    struct my_node *cur_node, *next_node;
    list_for_each_entry_safe(cur_node, next_node, &my_list, list) {
        printk(KERN_INFO "Removing %s\n", cur_node->str);
        list_del(&cur_node->list);
        kfree(cur_node->str);
        kfree(cur_node);
    }
}

module_init(my_module_init);
module_exit(my_module_exit);

MODULE_LICENSE("GPL");