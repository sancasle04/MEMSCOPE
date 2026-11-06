/*
 * memscope - a small Linux memory inspector
 *
 * Modes:
 *   memscope                   interactive menu (variables, arrays, pointers,
 *                              "where does this address live?", alloc demo)
 *   memscope map <pid>         memory map of a process, with per-type totals
 *   memscope watch <pid> [s]   re-read every s seconds, show what changed
 *
 * <pid> can also be the word "self".
 */
#define _POSIX_C_SOURCE 200809L

#include <ctype.h>
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define PATH_LEN 512

/* ------------------------------------------------------------------ */
/* Data types                                                          */
/* ------------------------------------------------------------------ */

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
    char path[PATH_LEN];
} Region;

/* A "reading": a growing list of regions taken at one moment. */
typedef struct {
    Region *items;
    size_t count;
    size_t cap;
} Snapshot;

/* ------------------------------------------------------------------ */
/* Snapshot list                                                       */
/* ------------------------------------------------------------------ */

static void snap_add(Snapshot *s, const Region *r)
{
    if (s->count == s->cap) {
        size_t newcap = s->cap ? s->cap * 2 : 64;
        Region *p = realloc(s->items, newcap * sizeof(Region));
        if (!p) {
            perror("realloc");
            exit(1);
        }
        s->items = p;
        s->cap = newcap;
    }
    s->items[s->count++] = *r;
}

static void snap_free(Snapshot *s)
{
    free(s->items);
    s->items = NULL;
    s->count = s->cap = 0;
}

/* ------------------------------------------------------------------ */
/* Parsing /proc/<pid>/smaps                                           */
/* ------------------------------------------------------------------ */

/* Returns 1 if the line is a region header like:
 * 7f1c2a000000-7f1c2a021000 rw-p 00000000 00:00 0      [heap]          */
static int parse_line(const char *line, Region *r)
{
    memset(r, 0, sizeof(*r));

    /* 511 = PATH_LEN - 1 */
    int n = sscanf(line, "%lx-%lx %4s %lx %11s %lu %511[^\n]",
                   &r->start, &r->end, r->perms,
                   &r->offset, r->dev, &r->inode, r->path);

    if (n < 6)
        return 0;
    return strlen(r->perms) == 4 &&
           (r->perms[3] == 'p' || r->perms[3] == 's');
}

/* Reads an smaps file into snap. Returns 0 on failure (errno is kept). */
static int read_smaps_file(const char *path, Snapshot *snap)
{
    FILE *fp = fopen(path, "r");
    if (!fp)
        return 0;

    char *line = NULL;
    size_t cap = 0;
    Region cur;
    int have = 0;

    while (getline(&line, &cap, fp) != -1) {
        Region next;
        unsigned long v;

        if (parse_line(line, &next)) {
            if (have)
                snap_add(snap, &cur);
            cur = next;
            have = 1;
        } else if (have) {
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
        snap_add(snap, &cur);

    free(line);
    fclose(fp);
    return 1;
}

static int read_smaps(const char *pid, Snapshot *snap)
{
    char path[64];
    snprintf(path, sizeof(path), "/proc/%s/smaps", pid);
    return read_smaps_file(path, snap);
}

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */

static int is_valid_pid(const char *s)
{
    if (strcmp(s, "self") == 0)
        return 1;
    if (*s == '\0')
        return 0;
    for (; *s; s++)
        if (!isdigit((unsigned char)*s))
            return 0;
    return 1;
}

static void report_open_error(const char *pid, int err)
{
    if (err == ENOENT || err == ESRCH)
        fprintf(stderr, "memscope: no such process: %s\n", pid);
    else if (err == EACCES || err == EPERM)
        fprintf(stderr, "memscope: permission denied for %s "
                        "(use your own process, or sudo)\n", pid);
    else
        fprintf(stderr, "memscope: cannot read process %s: %s\n",
                pid, strerror(err));
}

static void format_size(unsigned long bytes, char *out, size_t outlen)
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

static const char *classify(const Region *r)
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

/* ------------------------------------------------------------------ */
/* Printing                                                            */
/* ------------------------------------------------------------------ */

static int print_status(const char *pid)
{
    char path[64];
    snprintf(path, sizeof(path), "/proc/%s/status", pid);

    FILE *fp = fopen(path, "r");
    if (!fp) {
        report_open_error(pid, errno);
        return 0;
    }

    const char *wanted[] = { "Name:", "VmSize:", "VmRSS:", "VmData:",
                             "VmStk:", "VmExe:", "VmLib:" };
    size_t nwanted = sizeof(wanted) / sizeof(wanted[0]);

    char *line = NULL;
    size_t cap = 0;

    while (getline(&line, &cap, fp) != -1) {
        for (size_t i = 0; i < nwanted; i++) {
            if (strncmp(line, wanted[i], strlen(wanted[i])) == 0) {
                fputs(line, stdout);
                break;
            }
        }
    }

    free(line);
    fclose(fp);
    return 1;
}

static void print_row(const Region *r)
{
    char size_str[32];
    format_size(r->end - r->start, size_str, sizeof(size_str));

    printf("%-16lx %-16lx %-10s %-8lu %-8lu %-10lu %-7s %-8s %s\n",
           r->start, r->end, size_str,
           r->rss_kb, r->pss_kb, r->dirty_kb,
           r->perms, classify(r), r->path);
}

static void print_totals(const Snapshot *s)
{
    static const char *types[] = { "HEAP", "STACK", "SPECIAL",
                                   "ANON", "LIB", "FILE" };
    enum { NTYPES = sizeof(types) / sizeof(types[0]) };

    unsigned long count[NTYPES] = {0}, size[NTYPES] = {0};
    unsigned long rss[NTYPES] = {0}, pss[NTYPES] = {0}, dirty[NTYPES] = {0};

    for (size_t i = 0; i < s->count; i++) {
        const Region *r = &s->items[i];
        const char *t = classify(r);
        for (int k = 0; k < NTYPES; k++) {
            if (strcmp(types[k], t) == 0) {
                count[k]++;
                size[k]  += (r->end - r->start) / 1024;
                rss[k]   += r->rss_kb;
                pss[k]   += r->pss_kb;
                dirty[k] += r->dirty_kb;
                break;
            }
        }
    }

    unsigned long tc = 0, ts = 0, tr = 0, tp = 0, td = 0;

    printf("\n%-8s %-8s %-12s %-10s %-10s %-10s\n",
           "TYPE", "REGIONS", "SIZE(kB)", "RSS(kB)", "PSS(kB)", "DIRTY(kB)");
    for (int k = 0; k < NTYPES; k++) {
        printf("%-8s %-8lu %-12lu %-10lu %-10lu %-10lu\n",
               types[k], count[k], size[k], rss[k], pss[k], dirty[k]);
        tc += count[k]; ts += size[k]; tr += rss[k];
        tp += pss[k];   td += dirty[k];
    }
    printf("%-8s %-8lu %-12lu %-10lu %-10lu %-10lu\n",
           "TOTAL", tc, ts, tr, tp, td);
}

static void print_snapshot(const Snapshot *s)
{
    printf("%-16s %-16s %-10s %-8s %-8s %-10s %-7s %-8s %s\n",
           "START", "END", "SIZE", "RSS(kB)", "PSS(kB)",
           "DIRTY(kB)", "PERMS", "TYPE", "PATH");
    for (size_t i = 0; i < s->count; i++)
        print_row(&s->items[i]);
    print_totals(s);
}

/* ------------------------------------------------------------------ */
/* Comparing two readings                                              */
/* ------------------------------------------------------------------ */

/* Same region = same path AND (same start address OR same end address).
 * The heap keeps its start and grows its end; new mmap regions are placed
 * just below old ones, so they keep their end and the start moves down. */
static const Region *find_region(const Snapshot *s, const Region *r)
{
    for (size_t i = 0; i < s->count; i++)
        if (strcmp(s->items[i].path, r->path) == 0 &&
            (s->items[i].start == r->start || s->items[i].end == r->end))
            return &s->items[i];
    return NULL;
}

static void show_changes(const Snapshot *old, const Snapshot *cur)
{
    long total = 0;
    int any = 0;

    for (size_t i = 0; i < cur->count; i++) {
        const Region *n = &cur->items[i];
        const Region *o = find_region(old, n);

        if (!o) {
            printf("NEW   %-16lx %+8ld kB  %s\n",
                   n->start, (long)n->rss_kb, n->path);
            total += (long)n->rss_kb;
            any = 1;
        } else {
            /* cast to long first: unsigned subtraction would wrap around */
            long d = (long)n->rss_kb - (long)o->rss_kb;
            if (d != 0) {
                printf("      %-16lx %+8ld kB  %s\n",
                       n->start, d, n->path);
                total += d;
                any = 1;
            }
        }
    }

    for (size_t i = 0; i < old->count; i++) {
        const Region *o = &old->items[i];
        if (!find_region(cur, o)) {
            printf("GONE  %-16lx %+8ld kB  %s\n",
                   o->start, -(long)o->rss_kb, o->path);
            total -= (long)o->rss_kb;
            any = 1;
        }
    }

    if (!any)
        printf("(no change)\n");
    printf("TOTAL RSS change: %+ld kB\n", total);
}

/* ------------------------------------------------------------------ */
/* Command line modes: map and watch                                   */
/* ------------------------------------------------------------------ */

static volatile sig_atomic_t stop = 0;

static void on_sigint(int sig)
{
    (void)sig;
    stop = 1;
}

static int cmd_map(const char *pid)
{
    if (!print_status(pid))
        return 1;
    printf("\n");

    Snapshot s = {0};
    if (!read_smaps(pid, &s)) {
        report_open_error(pid, errno);
        return 1;
    }
    print_snapshot(&s);
    snap_free(&s);
    return 0;
}

static int cmd_watch(const char *pid, unsigned interval)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_sigint;
    sigaction(SIGINT, &sa, NULL);

    Snapshot old = {0};
    if (!read_smaps(pid, &old)) {
        report_open_error(pid, errno);
        return 1;
    }
    printf("Watching PID %s every %us. Ctrl-C to stop.\n", pid, interval);
    fflush(stdout);

    while (!stop) {
        sleep(interval);
        if (stop)
            break;

        Snapshot cur = {0};
        if (!read_smaps(pid, &cur)) {
            printf("\nProcess %s has ended.\n", pid);
            snap_free(&cur);
            break;
        }

        char stamp[16];
        time_t now = time(NULL);
        strftime(stamp, sizeof(stamp), "%H:%M:%S", localtime(&now));
        printf("\n--- %s: change over last %us ---\n", stamp, interval);
        show_changes(&old, &cur);
        fflush(stdout);

        snap_free(&old);
        old = cur;
    }

    snap_free(&old);
    return 0;
}

/* ------------------------------------------------------------------ */
/* Interactive menu                                                    */
/* ------------------------------------------------------------------ */

typedef struct {
    int a;
    double b;
    char c;
    int *arr;
    int n;
} Demo;

static int global_counter = 42;   /* a global, to see where globals live */

static const Region *region_containing(const Snapshot *s, unsigned long addr)
{
    for (size_t i = 0; i < s->count; i++)
        if (addr >= s->items[i].start && addr < s->items[i].end)
            return &s->items[i];
    return NULL;
}

static void inspect_variables(const Demo *d)
{
    puts("\n--- VARIABLE INSPECTION ---");

    printf("Integer value: %d\n", d->a);
    printf("Size: %zu bytes\n", sizeof(d->a));
    printf("Address: %p\n", (const void *)&d->a);

    printf("\nDouble value: %.4f\n", d->b);
    printf("Size: %zu bytes\n", sizeof(d->b));
    printf("Address: %p\n", (const void *)&d->b);

    printf("\nCharacter value: %c\n", d->c);
    printf("Size: %zu bytes\n", sizeof(d->c));
    printf("Address: %p\n", (const void *)&d->c);
}

static void inspect_array(const Demo *d)
{
    puts("\n--- ARRAY MEMORY INSPECTION ---");
    printf("Array base address: %p\n", (const void *)d->arr);
    printf("Total allocated size: %zu bytes\n", (size_t)d->n * sizeof(int));

    for (int i = 0; i < d->n; i++)
        printf("Index: %d | Value: %d | Address: %p\n",
               i, d->arr[i], (const void *)&d->arr[i]);
}

static void inspect_pointer(const Demo *d)
{
    puts("\n--- POINTER INSPECTION ---");

    const int *ptr = d->arr;

    printf("Pointer's own address: %p\n", (const void *)&ptr);
    printf("Address stored in pointer: %p\n", (const void *)ptr);
    printf("Value at pointed address: %d\n", *ptr);

    for (int i = 0; i < d->n; i++)
        printf("Index: %d | Address: %p | Dereferenced value: %d\n",
               i, (const void *)(ptr + i), *(ptr + i));
}

/* returns 0 on bad input that should end the program */
static int modify_memory(Demo *d)
{
    int index, num;

    puts("\n--- MEMORY MODIFICATION ---");
    printf("Enter the index (0 to %d): ", d->n - 1);
    if (scanf("%d", &index) != 1) {
        puts("Invalid index input.");
        return 0;
    }
    if (index < 0 || index >= d->n) {
        puts("Invalid index.");
        return 1;
    }

    printf("Enter the new value: ");
    if (scanf("%d", &num) != 1) {
        puts("Invalid value.");
        return 0;
    }

    printf("Original value: %d\n", d->arr[index]);

    int *ptr = &d->arr[index];
    *ptr = num;

    printf("Modified value through pointer: %d\n", *ptr);
    printf("Updated array element: %d\n", d->arr[index]);
    printf("Element address: %p\n", (void *)ptr);
    return 1;
}

/* Ask the OS: which memory region does each of these addresses live in? */
static void locate_addresses(Demo *d)
{
    puts("\n--- WHERE DOES EACH ADDRESS LIVE? ---");

    Snapshot s = {0};
    if (!read_smaps_file("/proc/self/smaps", &s)) {
        perror("read /proc/self/smaps");
        return;
    }

    const char *literal = "a string literal";
    int *local_ptr = d->arr;

    struct { const char *label; unsigned long addr; } items[] = {
        { "local int a",            (unsigned long)(uintptr_t)&d->a },
        { "local double b",         (unsigned long)(uintptr_t)&d->b },
        { "pointer variable",       (unsigned long)(uintptr_t)&local_ptr },
        { "calloc'd array (arr)",   (unsigned long)(uintptr_t)d->arr },
        { "global variable",        (unsigned long)(uintptr_t)&global_counter },
        { "string literal",         (unsigned long)(uintptr_t)literal },
        { "our own code (function)",(unsigned long)(uintptr_t)&locate_addresses },
        { "libc code (printf)",     (unsigned long)(uintptr_t)&printf },
    };

    printf("%-24s %-16s %-8s %-6s %s\n",
           "WHAT", "ADDRESS", "TYPE", "PERMS", "REGION PATH");
    for (size_t i = 0; i < sizeof(items) / sizeof(items[0]); i++) {
        const Region *r = region_containing(&s, items[i].addr);
        printf("%-24s %-16lx %-8s %-6s %s\n",
               items[i].label, items[i].addr,
               r ? classify(r) : "?",
               r ? r->perms : "?",
               r ? r->path : "(not found)");
    }

    puts("\nNote: a small calloc/malloc lands in [heap], but big requests "
         "(about 128 kB+)\nare served by mmap and show up as ANON instead.");
    snap_free(&s);
}

/* Allocate memory and watch RSS react: untouched memory costs nothing. */
static void alloc_demo(void)
{
    int mb;
    puts("\n--- ALLOCATION DEMO ---");
    printf("How many MB to allocate (1-1024)? ");
    if (scanf("%d", &mb) != 1 || mb < 1 || mb > 1024) {
        puts("Invalid size.");
        return;
    }

    Snapshot before = {0}, mid = {0}, after = {0};
    if (!read_smaps_file("/proc/self/smaps", &before)) {
        perror("read /proc/self/smaps");
        return;
    }

    size_t bytes = (size_t)mb * 1024 * 1024;
    volatile char *p = malloc(bytes);
    if (!p) {
        puts("Memory allocation failed.");
        snap_free(&before);
        return;
    }

    read_smaps_file("/proc/self/smaps", &mid);
    printf("\n1) After malloc(%d MB), before writing anything:\n", mb);
    show_changes(&before, &mid);

    for (size_t i = 0; i < bytes; i += 4096)   /* touch one byte per page */
        p[i] = 1;

    read_smaps_file("/proc/self/smaps", &after);
    printf("\n2) After writing to every page:\n");
    show_changes(&mid, &after);

    free((void *)p);
    snap_free(&before);
    snap_free(&mid);
    snap_free(&after);
}

static int run_menu(void)
{
    Demo d = {0};

    puts("ENTER THE INTEGER");
    if (scanf("%d", &d.a) != 1) {
        puts("Invalid integer.");
        return 1;
    }

    puts("ENTER THE DOUBLE");
    if (scanf("%lf", &d.b) != 1) {
        puts("Invalid double.");
        return 1;
    }

    puts("ENTER THE CHARACTER");
    if (scanf(" %c", &d.c) != 1) {
        puts("Invalid character.");
        return 1;
    }

    puts("ENTER THE SIZE OF ARRAY");
    if (scanf("%d", &d.n) != 1 || d.n <= 0) {
        puts("INVALID ARRAY SIZE");
        return 1;
    }

    d.arr = calloc((size_t)d.n, sizeof(int));
    if (!d.arr) {
        puts("Memory allocation failed.");
        return 1;
    }

    puts("Enter the array elements:");
    for (int i = 0; i < d.n; i++) {
        printf("arr[%d]: ", i);
        if (scanf("%d", &d.arr[i]) != 1) {
            puts("Invalid input.");
            free(d.arr);
            return 1;
        }
    }

    for (;;) {
        int choice;

        puts("\n========== MEMSCOPE ==========");
        puts("[1] Variable Inspection");
        puts("[2] Array Memory Inspection");
        puts("[3] Pointer Inspection");
        puts("[4] Memory Modification");
        puts("[5] Where does each address live? (stack/heap/code)");
        puts("[6] Full memory map of this program");
        puts("[7] Allocation demo (watch RSS change)");
        puts("[0] Exit");
        printf("Enter your choice: ");

        if (scanf("%d", &choice) != 1) {
            puts("Invalid input.");
            break;
        }

        if (choice == 0) {
            puts("Exiting MemScope.");
            break;
        }

        switch (choice) {
        case 1: inspect_variables(&d); break;
        case 2: inspect_array(&d);     break;
        case 3: inspect_pointer(&d);   break;
        case 4:
            if (!modify_memory(&d)) {
                free(d.arr);
                return 1;
            }
            break;
        case 5: locate_addresses(&d);  break;
        case 6: {
            Snapshot s = {0};
            if (read_smaps_file("/proc/self/smaps", &s)) {
                print_snapshot(&s);
                snap_free(&s);
            } else {
                perror("read /proc/self/smaps");
            }
            break;
        }
        case 7: alloc_demo();          break;
        default: puts("Invalid choice. Select 0 to 7."); break;
        }
    }

    free(d.arr);
    return 0;
}

/* ------------------------------------------------------------------ */
/* main                                                                */
/* ------------------------------------------------------------------ */

static void usage(const char *prog)
{
    fprintf(stderr,
            "Usage:\n"
            "  %s                      interactive menu\n"
            "  %s map <pid>            memory map of a process\n"
            "  %s watch <pid> [secs]   show memory changes every secs (default 2)\n"
            "<pid> may also be the word \"self\".\n",
            prog, prog, prog);
}

int main(int argc, char *argv[])
{
    if (argc == 1)
        return run_menu();

    if (strcmp(argv[1], "map") == 0 && argc == 3) {
        if (!is_valid_pid(argv[2])) {
            fprintf(stderr, "PID must be a number\n");
            return 1;
        }
        return cmd_map(argv[2]);
    }

    if (strcmp(argv[1], "watch") == 0 && (argc == 3 || argc == 4)) {
        if (!is_valid_pid(argv[2])) {
            fprintf(stderr, "PID must be a number\n");
            return 1;
        }
        unsigned interval = 2;
        if (argc == 4) {
            char *end;
            long v = strtol(argv[3], &end, 10);
            if (*end != '\0' || v < 1 || v > 3600) {
                fprintf(stderr, "interval must be 1-3600 seconds\n");
                return 1;
            }
            interval = (unsigned)v;
        }
        return cmd_watch(argv[2], interval);
    }

    usage(argv[0]);
    return 1;
}
