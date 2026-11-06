# memscope

A small Linux memory inspector written in C. It answers three questions:

1. **Where does my program's memory live?** (stack, heap, code, libraries)
2. **How much memory is a process really using?** (RSS vs PSS, per region type)
3. **Is something leaking?** (watch mode shows which region grows)

Linux only. It reads `/proc/<pid>/smaps` and `/proc/<pid>/status`, no libraries needed.

## Build

```
make          # builds memscope and the leak test program
make debug    # builds memscope with AddressSanitizer + UBSan
```

## Usage

```
./memscope                    interactive menu
./memscope map <pid>          memory map of a process, with totals
./memscope watch <pid> [s]    show what changed every s seconds (default 2)
```

`<pid>` can also be `self`. Reading another user's process needs `sudo`.

### Interactive menu

Enter an int, a double, a char and an array, then inspect them:

| Option | What it does |
|---|---|
| 1-3 | Show values, sizes and addresses of variables, the array, and a pointer |
| 4 | Change an array element through a pointer |
| 5 | Ask the OS which region each address lives in (stack, heap, code, library) |
| 6 | Print the full memory map of the running program |
| 7 | Allocate N MB and watch RSS react before and after writing to it |

Option 5 sample output:

```
WHAT                     ADDRESS          TYPE     PERMS  REGION PATH
local int a              7ffd5d4f3670     STACK    rw-p   [stack]
calloc'd array (arr)     55efe65692c0     HEAP     rw-p   [heap]
global variable          55efc0d30010     FILE     rw-p   /home/user/memscope
string literal           55efc0d2d0f2     FILE     r--p   /home/user/memscope
libc code (printf)       7f8c1a260100     LIB      r-xp   /usr/lib/.../libc.so.6
```

### Finding a leak with watch mode

```
./leak &                  # test program: leaks 1 MB per second
./memscope watch $!       # PID of the last background job
```

```
--- 03:45:07: change over last 2s ---
      7fb1426fd000        +2056 kB
TOTAL RSS change: +2056 kB
```

One region growing every interval is the signature of a leak.

## What the columns mean

| Column | Meaning |
|---|---|
| SIZE | Virtual size: address space reserved, not necessarily used |
| RSS | Memory actually in RAM for this region |
| PSS | RSS with shared pages divided among the processes sharing them. The closest number to "what this process really costs" |
| DIRTY | Pages modified since loading (private + shared) |
| TYPE | HEAP, STACK, LIB (`.so`), FILE (the executable), ANON (no file, usually mmap), SPECIAL (`[vdso]` etc.) |

RSS only counts pages that have been touched. `malloc(50 MB)` alone adds almost nothing; writing to the memory is what makes RSS grow. Menu option 7 demonstrates this.

## How watch mode works

1. Read `/proc/<pid>/smaps` into a list of regions (a snapshot).
2. Wait `s` seconds and take another snapshot.
3. Match regions between the two snapshots: same path, and same start *or* same end address. (The heap keeps its start and grows its end; new mmap regions are placed below old ones, so they keep their end.)
4. Print regions whose RSS changed, plus `NEW` and `GONE` regions and the total.
5. Exit cleanly on Ctrl-C or when the process ends.

## Compared to existing tools

`pmap -X` and `smem` show similar columns. memscope adds the address-to-region lookup for your own variables, the allocation demo, and diffing between samples.

## Limitations

- Matching is O(n^2) per sample, fine for hundreds of regions.
- Regions that merge or split between samples can show as NEW/GONE.
- Linux only (`/proc`).
