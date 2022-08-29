CSIE5374 Assignment4 - GROUP 6

Discription:
	We implemented a pseudo file system - SeccompFS, which exposes seccomp system call trace of the currently running processes and allows users to install seccomp filter for a targeted process on this assignment.

Explanation:
	Firstly, we created and initialized a FS by allocating root superblock, root inode, and root dentry. Then we created two files: "config", "begin" within the root.
	When writing the "config" file, it would check whether the format of the input string and system call number are valid or not. If it succeed, then you can write the "begin" file to attach the seccomp filter.
	When writing the "begin" file, it would call the function "seccomp_mode_filter"(kernel/seccomp.c) to attach filter to the designated running process.
	Filtered pids are stored in filtered array and use pid_cnt to count filtered processes.

BPF filter detail : 
	The system call number is first loaded into the struct sock_filter array from the data structure "seccomp_data".
	Then, for each allowed system call number in the array "config_info", we build a pair of BPF instructions to determine whether the system call matches any of the allowed system call numbers.
	The pair of instructions include a jump and return statement, if the system call number in seccomp_data match, then return SECCOMP_RET_ALLOW, jump one instruction forward otherwise.
	If the system call number in seccomp data matches, the pair of instructions returns SECCOMP_RET_ALLOW; otherwise, it jumps one instruction forward.
	The BPF instruction returns SECCOMP_RET_KILL_THREAD at the end of the filter array, indicating that the system call did not match any of the allowed system call numbers and that we should terminate this process.

Write log file:
	Add store_filter() function to "__seccomp_filter" to get log infomation, then open log file to write data to log file. Write log information one line each time.
	Only get data of pid which store in filtered array.


Contribution:
	游勝帆: SeccompFS(file_operation), Seccomp Filter, "config" file, Debugging 
	王祥宇: SeccompFS(superblock, dentry, create_file), "begin" file, write log file, Degubbing
	彭旻翊: SeccompFS(create_dir), "log" file, testing File, Write-up

References:
	1.	https://lwn.net/Articles/13325/
	2.	https://linux.die.net/lkmpg/x769.html
	3.	https://elixir.bootlin.com/linux/v5.4/source/kernel/seccomp.c
	4.  https://man7.org/linux/man-pages/man2/seccomp.2.html
	5.  https://www.cnblogs.com/zhangshenghui/p/7615146.html
	6.  https://blog.csdn.net/w968516q/article/details/77964853 