#include <cstdio>

class A {
public:
	virtual int cycle() = 0;
};

class B : public A {
public:
	int cycle();
};

int B::cycle()
{
	int i, j;
	int dst = 0;

	for (i = 0; i < 100000000; i++) {
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
	B b;

	asm ("mov $0, %%ecx\n\t" : :);
	b.cycle();

	return 0;
}
