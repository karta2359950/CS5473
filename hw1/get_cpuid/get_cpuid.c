#include <linux/kernel.h>
#include <asm/smp.h>
asmlinkage long sys_get_cpuid(void)
{
	return (long)raw_smp_processor_id();
}
