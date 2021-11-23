#include <stdio.h>
#include "lib_cycle.h"

int lib_cycle(void)
{
	int i, j;
	int dst = 0;

	for (i = 0; i < 1000; i++) {
		j = i * 2;
	}

	asm ("mov %%ecx, %0\n\t"
		: "=r" (dst)
		:);

	printf("dst2 = 0x%08x\n", dst);

	return j;
}
