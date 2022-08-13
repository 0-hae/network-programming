#include <stdio.h>
#include <stdint.h>
#include <netinet/in.h>

uint32_t read_file(char *argv)
{
	uint32_t buf, result;

	FILE* fp = fopen(argv, "rb");

	result = fread(&buf, 1, sizeof(uint32_t), fp);
	if(result == 0)
	{
		printf("fread error\n");
		return 1;
	}
	else 
		return buf;
}



int main(int argc, char **argv)
{
	uint32_t ret1, ret2;
	uint32_t sum;

	if(argc!=3)
	{
		printf("arg error\n");
		return 1;
	}

	ret1 = ntohl(read_file(argv[1]));
	ret2 = ntohl(read_file(argv[2]));

	sum = ret1 + ret2;

	printf("%d(0x%x) + %d(0x%x) = %d(0x%x)",ret1, ret1, ret2, ret2, sum, sum);
	return 0;
}
