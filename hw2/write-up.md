NTＵ CSIE5374 Assignment2 Write-up (Group no.6)

It's a simple rootkit, and there are 3 functions in it:
1.	Hide/unhide rootkit:
	To hide the rootkit from listing out through "lsomd", we create a list_head to save the original list entry and delete the list. 
	To unhide the rootkit, just add the original list again.

2.	Masquerade process name:
	To masquerade  process name, I pass data to kernel space by function copy_from_user(). In order to pass the list, I call function twice and get data by *local_list
	Then, use function for_each_process() to get every kernel task's name after compare old name and new name's length. 
	If old name is found in task, then change it to new name.

3.	Hook/unhook system calls:
	In order to hook three system calls(execve, reboot and write), the rootkit has to find the address of system call table first.
	We first use kallsyms_lookup_name function to find the the address of sys_call_table and update_mapping_prot functions(to make read-only section writeable).
	Next, we find rodata section and change this section to writeable(so we can change the content in sys_call_table).
	In the  last step, we change the execve, reboot and write function pointer in sys_call_table to our function pointer.

	For the write system call, we compare the user space string buffer. If the string is "Hello World!\n", then we change it into "byebyeworld\n\n".
	To test the write system call, please cross compile the write_test.c file and run it beofore/after the hooking. Thanks!

We provide the test files for each function.

Hide:				hide.c
Masqerade:			masqerade.c
Hook system call:	write_test.c, hook_test.c	(run hook test first)

Execute:
cd /PATH/TO/rootkit
make KDIR=/PATH/TO/linux-5.4-source CROSS=aarch64-linux-gnu-

After kernel module binary (i.e. rootkit.ko ) is generated, you can install it to a running kernel using the
insmod command:
sudo insmod rootkit.ko
dmesg | tail
	...
	[ 171.080020] The major number for your device is 236
	...
sudo mknod /dev/rootkit c 236 0
(change 236 to what you get from dmesg )


References:

	Hide:
	https://xcellerator.github.io/posts/linux_rootkits_05/

	Masqerade:
	https://stackoverflow.com/questions/55574155/copy-structure-with-included-user-pointers-from-user-space-to-kernel-space-copy

	Systemcall Hooking:
	https://stackoverflow.com/questions/59851520/system-call-hooking-example-arguments-are-incorrect
