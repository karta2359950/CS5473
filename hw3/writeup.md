compile : git apply patch and then use makefile in the file to generate test binary
execute : ./test -i pid begin_va end_va
explanation : First copy args from user space, then find reserved vma. Use kmalloc_array to malloc ftlb, then find pte table by given VA. find_pte find given va's pte table's pfn.
remap pte table if found and construct ftlb in the for loop. Finally, remap ftlb. find_pte use kernel function to check whether the va has pa or not, if found, then return pte's pfn.

System call detail :
	1. First, we use pid to search for the correspoding task_struct.
	2. Using this task_struct's mm_struct to walk the page tables with MACRO functions defined in /arch/arm64/include/asm/pgtable.h, if the input virtual addresss has pte table, return it's pfn.
	3. remap the founded pte table to vma reserved from user program, and assign it's remapped va address to flattened table.

Problem : 
	1. syscall' return ftlb value maybe wrong in some unexpected case. So the print *pa cause segentation fault.
contribution :  
	r10944064:system call
	r09944064:system call/inspection
	r10922172:inspection
ref:https://www.zendei.com/article/41768.html
	https://stackoverflow.com/questions/20025183/find-page-in-memory-for-process-linux-kernel
	https://github.com/torvalds/linux/blob/master/lib/test_debug_virtual.c
	http://myblog-maurice.blogspot.com/2011/12/linux_7692.html
