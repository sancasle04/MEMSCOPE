#include <stdio.h>
#include "cpu.h" 
int cpu_read(cpu_times_t *t)
{
	char buffer[256];
	FILE *f = fopen("/proc/stat","r");
	if (f ==NULL)
	{
		perror("cannot open file");
		return -1;
	}
	if (fgets(buffer,sizeof(buffer),f)==NULL)
	{ fclose(f);
		return -1;
	}
	fclose(f);
	int n = sscanf(buffer,"cpu %llu %llu %llu %llu %llu %llu %llu %llu",
	&t->user,&t->nice,&t->system,&t->idle,&t->iowait,
	&t->HardRQ,&t->SoftRQ,&t->steal);
	
	if (n!=8)
	{
		fprintf(stderr, "parsing failed\n");
		return -1;
	}
	return 0;
}

double cpu_usage(const cpu_times_t *prev, const cpu_times_t *cur)
{
	unsigned long long idle_prev= prev->idle+prev->iowait;
	unsigned long long idle_cur=cur->idle+cur->iowait;
	
	unsigned long long busy_prev = prev->user+prev->nice+prev->system+
	                               prev->HardRQ+prev->SoftRQ+prev->steal;
	unsigned long long busy_cur = cur->user+cur->system+cur->steal+
	                              cur->nice+cur->SoftRQ+cur->HardRQ;
	
	unsigned long long total_cur = busy_cur+idle_cur;
	unsigned long long total_prev = busy_prev+idle_prev;
	

	unsigned long long delta_total = total_cur - total_prev;
	unsigned long long delta_busy = busy_cur-busy_prev;
	
	if (delta_total==0)
	{
		return 0.0;
	} 
	return (double)delta_busy*100/(double)delta_total ;
}

