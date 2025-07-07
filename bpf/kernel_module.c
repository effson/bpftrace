#include <linux/module.h>
#include <linux/kernel.h>

// insmod kernal_module.ko
static int kernal_module_init(void) {
    printk(KERN_INFO "Kernal Module Initialized\n");
    return 0; // Return 0 on success
} 
// rmmod kernal_module
static void kernal_module_exit(void) {
    printk(KERN_INFO "Kernal Module Exited\n");
}

module_init(kernal_module_init);
module_exit(kernal_module_exit);

MODULE_LICENSE("GPL");
