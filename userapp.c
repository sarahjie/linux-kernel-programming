#include "userapp.h"

//#define DEBUG 1
//stdio.h BUFSIZ 8192
int main(int argc, char* argv[])
{
	
	FILE *status_file = fopen("/proc/mp1/status", "w");
	if(status_file == NULL){
		printf("fopen failed\n");
		return 0;
	}
	pid_t pid = getpid();
	if (status_file) {

		int ret=fprintf(status_file, "%d", pid);
		#ifdef DEBUG
		printf("status file open");

		if (ret <0){
			printf("fprintf error %d \n",ret);
		};
		#endif

		fclose(status_file);
	}
	#ifdef DEBUG
	struct stat st;
	#endif
	int i, random;
	unsigned long int n;
	time_t start = time(NULL);
	while (time(NULL) - start < 10) {
		random = rand() % 12;
		n = 1;
		for (i = 1; i <= random; i++)
			n *= i;
		//printf("%d! = %lu\n", random, n);
	}

	int fd = open("/proc/mp1/status", O_RDONLY);
	if (fd<0){
		printf("failed to read file%d\n",fd);
		return 0;
	}
	if (fd >= 0) {
		char temp_buf[BUFSIZ-1];
		read(fd, temp_buf, BUFSIZ);
		puts(temp_buf);
		close(fd);
	}
	return 0;
}

