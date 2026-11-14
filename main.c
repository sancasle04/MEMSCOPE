#include <stdio.h>
#include <unistd.h>
#include "cpu.h"

int main()
{
	cpu_times_t prev,cur;
	
	if (cpu_read(&prev)==-1)
	{
		fprintf(stderr, "reading failed\n");
		return 1;
	}
	while(1)
	{
		sleep(1);
		if (cpu_read(&cur)==-1)
		{
			fprintf(stderr, "reading 1 failed\n");
		    return 1;
		}
		double a;
		a = cpu_usage(&prev,&cur);
		printf("cpu %.1f%%\n",a);
		prev = cur;
	}
		
		return 0;
	}
