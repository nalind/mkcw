#include <string.h>
#include <unistd.h>
int
main(int argc, char **argv)
{
	const char *msg = "This image is designed to be run using krun.\n";
	write(STDERR_FILENO, msg, strlen(msg));
	return 1;
}
