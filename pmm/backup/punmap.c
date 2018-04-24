/*
 * pmm/punmap.c
 *
 * Written by xzhao.
 *
 * Persistent memory region accounting code	<i@xuzhao.net>
 */
#include <linux/syscalls.h>
#include <linux/mm.h>

static unsigned long vm_punmap(unsigned long addr, len);

// todo: change punmap interface to let it accept char* names
SYSCALL_DEFINE2(punmap, unsigned long, addr, size_t, len) {
    return vm_munmap(addr, len);
}

/*
 * syscall punmap
 */
unsigned long vm_punmap(unsigned long addr, len) {
   int ret;
   struct mm_struct *mm = current->mm;
   LIST_HEAD(uf);
   if(down_write_killable(&mm->mmap_sem)) return -EINTR;
   ret = do_munmap(mm, start, len, &uf);
   up_write(&mm->:mmap_sem);
   return ret;
}
