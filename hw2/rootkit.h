#ifndef __ROOTKIT_HW2_H
#define __ROOTKIT_HW2_H

#include <linux/ioctl.h>

#define IOC_MAGIC 'd'
#define IOCTL_MOD_HOOK 1
#define IOCTL_MOD_HIDE _IO(IOC_MAGIC, 2)
#define IOCTL_MOD_MASQ 3

#define MASQ_LEN	20
struct masq_proc {
	char new_name[MASQ_LEN];
	char orig_name[MASQ_LEN];
};

struct masq_proc_req {
	size_t len;
	struct masq_proc *list;
};

#endif /* __ROOTKIT_HW2_H */
