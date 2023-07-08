/*  
 * main.c - The entry point to the module.
 */
#include <linux/module.h>	/* Needed by all modules */
#include <linux/kernel.h>	/* Needed for KERN_INFO */
#include <linux/hid.h>
#include <linux/irqnr.h>

MODULE_AUTHOR("jng");
MODULE_LICENSE("GPL");


/**
 * Module Init. Registers a USB device and creates a misc device in /dev/ft_module_keyboard
*/
int init_module(void)
{
	printk("hello worldddd\n");
}

void cleanup_module(void)
{

	
}
