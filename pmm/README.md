# Add a system call
- arch/x86/entry/syscalls/syscall_64.tbl
# Added by Xu
333  common    pbrk         sys_pbrk
334  common    pattach         sys_pattach
335  common    pdetach       sys_pdetach
336  common    pchmod        sys_pchmod

- include/uapi/asm-generic/unistd.h
/* Begin: added by Xu */
#define __NR_pbrk 292
__SYSCALL(__NR_pbrk, sys_pbrk)
#define __NR_pattach 293
__SYSCALL(__NR_pattach, sys_pattach)
#define __NR_pdetach 294
__SYSCALL(__NR_pdetach, sys_pdetach)
#define __NR_pchmod 295
__SYSCALL(__NR_pchmod, sys_pchmod)

#undef __NR_syscalls
/* #define __NR_syscalls 292 */ /* original */
#define __NR_syscalls 296 /* modifieded by Xu */

- include/linux/syscalls.h
asmlinkage long sys_pbrk(unsigned long pbrk);
asmlinkage long sys_pattach(const __user char *guid, size_t len, unsigned long flag);
asmlinkage long sys_pdetach(void);
asmlinkage long sys_pchmod(unsigned long mode);

- kernel/sys_ni.c
cond_syscall(sys_pbrk);
cond_syscall(sys_pattach);
cond_syscall(sys_pdetach);
cond_syscall(sys_pchmod);

