#include <stdio.h>

int cycle(void)
{
	int i, j;
	int dst = 0;

	for (i = 0; i < 1000; i++) {
		j = i * 2;
	}

	asm ("mov %%ecx, %0\n\t"
		: "=r" (dst)
		:);

	printf("dst = 0x%08x\n", dst);

	return j;
}

int main(void)
{
	asm ("mov $0, %%ecx\n\t" : :);
	cycle();

	return 0;
}
