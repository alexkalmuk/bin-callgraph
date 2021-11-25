#include <stdio.h>
#include <test/shared_lib/lib/lib_cycle.h>

static int cycle(void)
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

int main(void)
{
	asm ("mov $0, %%ecx\n\t" : :);
	cycle();

	asm ("mov $0, %%ecx\n\t" : :);
	lib_cycle();

	return 0;
}
