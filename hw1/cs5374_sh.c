#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <errno.h>

void signal_handler(int signum);
void cd(char *path);
void run(void);
char *argv[131073];
int main(void)
{
	char line[65535];

	signal(SIGINT, signal_handler);
	while (1) {
		/* Print the command prompt */
		printf("$");
		fflush(NULL);

		/* Read a command line */
		if (!fgets(line, sizeof(line), stdin)) {
			fprintf(stderr, "error: %s\n", strerror(errno));
			continue;
		}

		if (strcmp(line, "\n") == 0) {
			fprintf(stderr, "error: %s\n", "No input");
			continue;
		}

		if (strcmp(line, " \n") == 0) {
			fprintf(stderr, "error: %s\n", "No Argument");
			continue;
		}

		char *tmp = NULL;

		tmp = strstr(line, "\n");
		*tmp = '\0';
		tmp = NULL;
		free(tmp);

		int argc = 0;

		argv[argc] = strtok(line, " ");
		while (argv[argc]) {
			argc++;
			argv[argc] = strtok(NULL, " ");
			if(argv[131072])
				break;
		}

		if(argv[131072]){
			fprintf(stderr, "error: %s\n", "Too many Argument");
			continue;
		}

		if (strcmp(argv[0], "exit") == 0)
			return 0;

		else if (strcmp(argv[0], "cd") == 0)
			cd(argv[1]);

		else if (strcmp(argv[0], "getcpu") == 0){
			long cpuid = syscall(436);
			if(cpuid == -1){
				fprintf(stderr, "error: %s\n", strerror(errno));
				continue;
			}
			printf("%ld\n", cpuid);
		}

		else
			run();
	}
}

void signal_handler(int signum)
{
	if (signum == SIGINT) {
		printf("\n");
		_exit(0);
	}
}

void cd(char *path)
{
	if (chdir(path) == -1)
		fprintf(stderr, "error: %s\n", strerror(errno));
}

void run(void)
{
	pid_t pid;
	/* fork another process */
	pid = fork();
	if (pid < 0) { /* error occurred */
		fprintf(stderr, "error: %s\n", "Fork Failed");
	}
	else if (pid == 0) { /* child process */
		int status = execv(argv[0], argv);

		if (status == -1) {
			fprintf(stderr, "error: %s\n", strerror(errno));
			exit(-1);
		}
		exit(0);
	} else { /* parent process */
		wait(NULL);
	}
}
