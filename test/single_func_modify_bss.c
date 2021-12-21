#include <stdio.h>

int cycle(void)
{
	int i, j;

	for (i = 0; i < 1000; i++) {
		j = i * 2;
	}

	return j;
}

int main(void)
{
	cycle();

	return 0;
}
