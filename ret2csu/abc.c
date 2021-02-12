#include <stdio.h>

int main() {
	char buff[80];
	write(1, "buff:", 5);
	gets(&buff);
	return 0;
}
