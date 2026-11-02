#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>

typedef struct {
    unsigned long start;
    unsigned long end;
    char perms[5];
    unsigned long offset;
    char dev[12];
    unsigned long inode;
    unsigned long rss_kb;     
    unsigned long pss_kb;     
    unsigned long dirty_kb;   
    char path[4096];
} Region;

int parse_line(const char *line, Region *r)
{
    r->path[0] = '\0';
     r->rss_kb = 0; 
    r->pss_kb = 0;
    r->dirty_kb = 0;

    int n = sscanf(line, "%lx-%lx %4s %lx %11s %lu %4095[^\n]",
                   &r->start, &r->end, r->perms,
                   &r->offset, r->dev, &r->inode, r->path);

    return n >= 6;
}

void format_size(unsigned long bytes, char *out, size_t outlen)
{
    if (bytes >= 1024UL * 1024 * 1024)
        snprintf(out, outlen, "%.1f GB", bytes / (1024.0 * 1024.0 * 1024.0));
    else if (bytes >= 1024UL * 1024)
        snprintf(out, outlen, "%.1f MB", bytes / (1024.0 * 1024.0));
    else if (bytes >= 1024UL)
        snprintf(out, outlen, "%.1f KB", bytes / 1024.0);
    else
        snprintf(out, outlen, "%lu B", bytes);
}

const char *classify(const Region *r)
{
    if (strcmp(r->path, "[heap]") == 0)
        return "HEAP";
    if (strncmp(r->path, "[stack", 6) == 0)
        return "STACK";
    if (r->path[0] == '[')
        return "SPECIAL";
    if (r->path[0] == '\0')
        return "ANON";
    if (strstr(r->path, ".so") != NULL)
        return "LIB";
    return "FILE";
}

int is_number(const char *s)
{
    if (*s == '\0')
        return 0;
    for (; *s; s++)
        if (!isdigit((unsigned char)*s))
            return 0;
    return 1;
}

int print_status(const char *pid)
{
    char path[64];
    snprintf(path, sizeof(path), "/proc/%s/status", pid);

    FILE *fp = fopen(path, "r");
    if (!fp) {
        fprintf(stderr, "unable to read %s: %s\n", path, strerror(errno));
        return 0;
    }

    const char *wanted[] = { "Name:", "VmSize:", "VmRSS:", "VmData:",
                             "VmStk:", "VmExe:", "VmLib:" };
    size_t nwanted = sizeof(wanted) / sizeof(wanted[0]);

    char *line = NULL;
    size_t cap = 0;

    while (getline(&line, &cap, fp) != -1) {
        for (size_t i = 0; i < nwanted; i++) {
            size_t len = strlen(wanted[i]);
            if (strncmp(line, wanted[i], len) == 0) {
                fputs(line, stdout);
                break;
            }
        }
    }

    free(line);
    fclose(fp);
    return 1;
}

void print_row(const Region *r)
{
    char size_str[32];
    format_size(r->end - r->start, size_str, sizeof(size_str));

    printf("%-16lx %-16lx %-10s %-8lu %-8lu %-10lu %-7s %-8s %s\n",
           r->start, r->end, size_str,
           r->rss_kb, r->pss_kb, r->dirty_kb,
           r->perms, classify(r), r->path);
}

int print_smaps(const char *pid)
{
	snprintf(path,sizeof(path,"proc/%s/smaps",pid);
	FILE *fp = fopen(path,"r");
	if (!fp)
	{
		fprintf(stderr,"unable to read %s %s ",path,strerror(errno));
		return 0;
	}
	printf("%-16s %-16s %-10s %-8s %-8s %-10s %-7s %-8s %s\n",
           "START", "END", "SIZE", "RSS(kB)", "PSS(kB)",
           "DIRTY(kB)", "PERMS", "TYPE", "PATH");
    
    
    
    char *line = NULL;
    size_t cap = 0;
    Region cur;           
    int have = 0;         

    while (getline(&line, &cap, fp) != -1) {
        Region next;
        unsigned long v;

        if (parse_line(line, &next)) {             
            if (have)
                print_row(&cur);                   
            cur = next;
            have = 1;
        }
        else if (have) {                           
            if (sscanf(line, "Rss: %lu", &v) == 1)
                cur.rss_kb = v;
            else if (sscanf(line, "Pss: %lu", &v) == 1)
                cur.pss_kb = v;
            else if (sscanf(line, "Private_Dirty: %lu", &v) == 1)
                cur.dirty_kb += v;
            else if (sscanf(line, "Shared_Dirty: %lu", &v) == 1)
                cur.dirty_kb += v;
        }
    }

    if (have)
        print_row(&cur);                            

    free(line);
    fclose(fp);
    return 1;
}




int main(int argc, char *argv[])
{
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <pid>\n", argv[0]);
        return 1;
    }

    if (!is_number(argv[1])) {
        fprintf(stderr, "PID must be a number\n");
        return 1;
    }

    print_status(argv[1]);
    printf("\n");

    if (!print_smaps(argv[1]))
        return 1;

    return 0;
}
