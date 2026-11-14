#ifndef CPU_H
#define CPU_H
typedef struct
{unsigned long long user,nice,system,
	idle,iowait,HardRQ,SoftRQ,steal;
}cpu_times_t;
int cpu_read(cpu_times_t *t);
double cpu_usage(const cpu_times_t *prev, const cpu_times_t *cur);
#endif
