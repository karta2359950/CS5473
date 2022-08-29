#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

struct expose_pte_args {
        pid_t pid;
        unsigned long begin_fpt_vaddr;
        unsigned long end_fpt_vaddr;
        unsigned long begin_pte_vaddr;
        unsigned long end_pte_vaddr;
        unsigned long begin_vaddr;
        unsigned long end_vaddr;
};

unsigned long translate_pa(unsigned long va, unsigned long pa){
	pa = pa << 24;
	pa = pa >> 8;
	va = va & 0x00000000111;
	unsigned long translated_result = va + pa;
	return translated_result;
}

void print_page_info(struct expose_pte_args test, unsigned long *ftlb_addr, unsigned long *ptet) {
	int count = 0;
	unsigned long *pa = NULL;
	unsigned long va;
	for (va = test.begin_vaddr; va < test.end_vaddr; va += 4096) {
		int f_index = (int)((va-test.begin_vaddr)/4096);
		pa = (unsigned long *)*(ftlb_addr + f_index);
//		unsigned long *remapped_pte = *(ftlb_addr + f_index);
//		if (remapped_pte == 0){
//			printf("ha\n");
//			pa = 0;
//		} else {
//			pa = *remapped_pte;
//		}
		count += 1;
		if(pa){
			printf("va%d %lx\tpa%d %lx\n", count, va, count, translate_pa(va, *pa));
		}
		else{
			printf("va%d %lx\tpa not found", count, va);
		}
	}
}

int main(int argc, char* argv[])
{
	struct expose_pte_args test_args;

	char *command = "-i";
	if (argc == 5) {
		if(!strcmp(argv[1], command)) {
			test_args.pid = atoi (argv[2]);
			test_args.begin_vaddr = strtoul(argv[3], NULL, 16);
			test_args.end_vaddr = strtoul(argv[4], NULL, 16);

			if((test_args.begin_vaddr % 4096 != 0) || (test_args.end_vaddr % 4096 != 0)){
				printf("Invalid addresses\n");
				return 0;
			}
			/* mmap(test) */
			unsigned long *ftlb_addr = (unsigned long *)mmap(NULL, 4096*5, 
					PROT_READ | PROT_WRITE | PROT_EXEC, 
					MAP_ANONYMOUS|MAP_SHARED, -1, 0); 

			unsigned long *remapped_addr = (unsigned long *)mmap(NULL, 
					4096 *10, 
					PROT_READ | PROT_WRITE | PROT_EXEC, MAP_ANONYMOUS|MAP_SHARED, -1, 0);

			test_args.begin_fpt_vaddr = (unsigned long)ftlb_addr;
			test_args.end_fpt_vaddr = test_args.begin_fpt_vaddr + 4096*5;
			test_args.begin_pte_vaddr = (unsigned long)remapped_addr;
			test_args.end_pte_vaddr = test_args.begin_pte_vaddr + 4096*10;

			if(ftlb_addr == MAP_FAILED || remapped_addr == MAP_FAILED) {
				printf("failed to mmap\n");
				return -1;
			}
			/* syscall */
			long ret = syscall(436, test_args);
			if(ret < 0){
				printf("pte not found\n");
				return -1;
			}
			/* print out */
			print_page_info(test_args, ftlb_addr, remapped_addr);
		}
		else {
			printf("Invalid arguments.");
		}
	}
	else {
		printf("Too many or few arguments.\n");
		return -1;
	}

	return 0;
}
