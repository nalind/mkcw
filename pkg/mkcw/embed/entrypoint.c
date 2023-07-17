#include <string.h>
#include <unistd.h>
int
main(int argc, char **argv)
{
	const char *msg = "This image is designed to be run as a confidential workload using libkrun.\n";
	write(STDERR_FILENO, msg, strlen(msg));
	return 1;
}
