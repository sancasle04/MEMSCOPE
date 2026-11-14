#include <stdio.h>
#include <string.h>
#include "mem.h"

int mem_read(mem_info_t *m)
{
	FILE *fp;
	char buffer[256];
	char key[64];
	unsigned long long val;
	int found = 0;
	fp = fopen("/proc/meminfo","r");
	
	if (fp==NULL)
	{
		perror("cannot open file");
		return -1;
	}
	
	m->total=0;
	m->swap_free=0;
	m->swap=0;
	m->available=0;
	
	while (fgets(buffer,sizeof(buffer),fp)!=NULL)
	{
		{
		if (sscanf(buffer,"%63[^:]: %llu",key, &val)!=2)
		continue;
		}
		if (strcmp(key,"MemTotal")==0)
		{
			m->total = val;
			found++;
		}
		if (strcmp(key,"MemAvailable")==0)
		{
			m->available= val;
			found++;
		}
		if (strcmp(key,"SwapTotal")==0)
		{
			m->swap = val;
			found++;
		}
		if (strcmp(key,"SwapFree")==0)
		{
			m->swap_free = val;
			found++;
			}
		}
	fclose(fp);
	return (found == 4)?0:-1;
}

double swap_used_pct(const mem_info_t *m)
{
	if (m->swap == 0) {return 0.0;}
	return (m->swap-m->swap_free)*100.0/m->swap;
}
double mem_used_pct(const mem_info_t *m)
{
	if (m->total==0)
	{return 0.0;}
	return (m->total-m->available)*100.0/m->total;
	
}
