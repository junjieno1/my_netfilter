#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>

static struct task_struct *thread1;
static struct task_struct *thread2;

static int thread_fn(void *data)
{
    while (!kthread_should_stop()) {
        printk(KERN_INFO "Thread is running\n");
        ssleep(5);
    }
    printk(KERN_INFO "Thread stopped\n");
    return 0;
}

static int __init init_thread(void)
{
    printk(KERN_INFO "Creating threads\n");
    thread1 = kthread_create(thread_fn, NULL, "mythread1");
    thread2 = kthread_create(thread_fn, NULL, "mythread2");
    if (IS_ERR(thread1) || IS_ERR(thread2)) {
        printk(KERN_ERR "Threads creation failed\n");
        return -1;
    }
    wake_up_process(thread1);
    wake_up_process(thread2);
    printk(KERN_INFO "Threads created successfully\n");
    return 0;
}

static void __exit cleanup_thread(void)
{
    printk(KERN_INFO "Cleaning up threads\n");
    kthread_stop(thread1);
    kthread_stop(thread2);
}


module_init(init_thread);
module_exit(cleanup_thread);


MODULE_LICENSE("GPL");