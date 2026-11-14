#ifndef MEM_H
#define MEM_H

typedef struct
{
    unsigned long long total, available, swap, swap_free;
} mem_info_t;

int    mem_read(mem_info_t *m);
double mem_used_pct(const mem_info_t *m);
double swap_used_pct(const mem_info_t *m);

#endif