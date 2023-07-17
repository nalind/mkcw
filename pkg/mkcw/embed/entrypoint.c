#include <string.h>
#include <unistd.h>
int
main(int argc, char **argv)
{
	const char *msg = "This image is designed to be run as a confidential workload using libkrun.\n";
	if (write(STDERR_FILENO, msg, strlen(msg)) != strlen(msg)) {
		return 2;
	}
	return 1;
}
