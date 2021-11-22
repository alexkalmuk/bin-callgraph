#include <stdio.h>

int cycle_1(void)
{
	int i, j;
	int dst = 0;

	for (i = 0; i < 1000; i++) {
		j = i * 2;
	}

	asm ("mov %%ecx, %0\n\t"
		: "=r" (dst)
		:);

	printf("dst1 = 0x%08x\n", dst);

	return j;
}

int cycle_2(void)
{
	int i, j;
	int dst = 0;

	for (i = 0; i < 1000; i++) {
		j = i * 3;
	}

	asm ("mov %%ecx, %0\n\t"
		: "=r" (dst)
		:);

	printf("dst2 = 0x%08x\n", dst);

	return j;
}

int main(void)
{
	asm ("mov $0, %%ecx\n\t" : :);
	cycle_1();

	asm ("mov $0, %%ecx\n\t" : :);
	cycle_2();

	return 0;
}
