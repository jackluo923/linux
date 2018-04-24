#include <linux/syscalls.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/rmap.h>
#include <linux/security.h>
#include "pmm.h"

static unsigned long do_pmmap(unsigned long pmm_addr, unsigned long len);
static unsigned long get_punmapped_area(unsigned long addr, unsigned long len, unsigned long flags);
static unsigned long pmap_region(unsigned long addr, unsigned long len, vm_flags_t vm_flags, struct list_head *uf);
static void unmap_region(struct mm_struct *mm, struct vm_area_struct *vma, struct vm_area_struct *prev, 
    unsigned long start, unsigned long end);

/*
 * Several assumptions:
 * 1. For now we populate all memory pages at the beginning (should be fixed though)
 */
SYSCALL_DEFINE3(pmap, const char __user *, pmmid, size_t, idsize, unsigned long, pmm_addr, unsigned long, pmm_len) {
  unsigned long ret = 0;
  struct mm_struct *mm = current->mm;
  unsigned long populate = 0;
  char pmmid_buf[PMMID_LEN_LIMIT];
  LIST_HEAD(uf);

  // validate pmmid_len
  if(idsize > PMMID_LEN_LIMIT) {
    return -EINVAL; // invalid input value
  }
  // read in pmm_id from userland (resembles write syscall readin)
  // write syscall: fs/read_write.c
  
  copy_from_user(pmmid_buf, pmmid, idsize);
  // TODO: check if ret == n: means copy is successful
  // check if there is pmm_id conflict
  if(pmm_check_id_conflict(pmmid_buf) != -1) {
    return -EINVAL;
  }
  
  // start to allocate pmmap region
  // resembles mmap syscall source code, see: vm_mmap_pgoff in mm/util.c
  
  if(down_write_killable(&mm->mmap_sem)){ // lock mmap semaphore
      return -EINTR;
  }
  ret = do_pmmap(pmm_addr, pmm_len, &populate, &uf);
  up_write(&mm->mmap_sem); // unlock mmap semaphore
  // by default, populate and do the bookkeeping
  mm_populate(ret, populate);
  // TODO: bookkeeping on the physical pages
  return ret;
}

/*
 * Several assumptions of calling pmmap comparing to normal mmap:
 * 1. we assume MAP_PRIVATE - pgoff == (pmm_addr >> PAGE_SHIFT), i.e. there is no MAP_SHARED
 * 2. we assume MAP_FIXED - we don't call round_hint_to_min() to move the pmap target address
 * 3. we assume prog == PROT_READ | PROT_WRITE, but not PROT_EXEC, to execute pmem, you have to call execv()
 *    that is to say, you can't directly run a program from persistent memory.
 * By Xu
 */
unsigned long do_pmmap(unsigned long pmm_addr, unsigned long len,
             unsigned long *populate, struct list_head *uf) {
  struct mm_struct *mm = current->mm;
  int pkey = 0;
  unsigned long prot = 0;
  unsigned long vm_flags = 0;
  unsigned long pgoff = pmm_addr >> PAGE_SHIFT;
  
  *populate = 0;
  
  // check if pmm_addr is valid
  if(!len) {
      return -EINVAL;
  }
  
  /* Careful about overflows ... */
  len = PAGE_ALIGN(len);
  if(!len) {
    return -ENOMEM;
  }
  /* offset overflow? */
  if((pgoff + (len >> PAGE_SHIFT)) < pgoff)
      return -EOVERFLOW;
  
  /* Too many mappings? */
  if (mm->map_count > sysctl_max_map_count) {
    return -ENOMEM;
  }
  
  /* Sanity checks are done. 
   * Now we start to allocate new memory region. */
  
  // By default, we do not provide exec on pmm region. Read/write is always permitted.
  prot |= PROT_READ;
  prot |= PROT_WRITE;
  
  addr = get_punmapped_area(addr, len, vm_flags);
  if(offset_in_page(addr)) {
    printk("[do_pmmap] We observer an in-page offset in addr: %lu", addr);
    return addr;
  }
  
  /* Do simple checking here so the lower-level routines won't have
   * to. we assume access permissions have been handled by the open
   * of the memory object, so we don't do any here.
   */
  vm_flags |= calc_vm_prot_bits(prot, pkey) | calc_vm_flag_bits(flags) |
           mm->def_flags | VM_MAYREAD | VM_MAYWRITE | VM_MAYEXEC;
  // we don't have file concept in persistent memory
  switch(vm_flags & MAP_TYPE) {
  case MAP_PRIVATE:
      pgoff = addr >> PAGE_SHIFT;
      break;
  case MAP_SHARED:
      // we do not support MAP_SHARED, because share is done by share memory interface
      return -EINVAL;
  default:
      return -EINVAL;
  }
  addr = pmap_region(addr, len, vm_flags);
  if(!IS_ERR_VALUE(addr)) {
    *populate = len;
  }
  return addr;
}

unsigned long get_punmapped_area(unsigned long addr, unsigned long len,
                                 unsigned long pgoff, unsigned long flags) {
    unsigned long (*get_area)(struct file *, unsigned long,
				  unsigned long, unsigned long, unsigned long);
    
    unsigned long error = arch_mmap_check(addr, len, flags);
    if(error) {
        return error;
    }
    if(len > TASK_SIZE) return -ENOMEM;
    get_area = current->mm->get_unmapped_area;
    // we skip file->f_op->get_unmapped_area and shmem_get_unmapped_area,
    // and directly use current->mm->get_unmapped_area
    addr = get_area(NULL, addr, len, pgoff, flags);
    if(IS_ERR_VALUE(addr)) {
        return addr;
    }
    
    if(addr > TASK_SIZE - len) {
        return -ENOMEM;
    }
    if(offset_in_page(addr)) {
        return -EINVAL;
    }
    error = security_mmap_addr(addr);
    return error ? error : addr;
}

unsigned long pmap_region(unsigned long addr, unsigned long len, vm_flags_t vm_flags, struct list_head *uf) {
    struct mm_struct *mm = current->mm;
    struct vm_area_struct *vma, *prev;
    int error;
    struct rb_node **rb_link, *rb_parent;
    unsigned long charged = 0;
    
    /* Clear old maps */
    while (find_vma_links(mm, addr, addr + len, &prev, &rb_link, &rb_parent)) {
        if(do_munmap(mm, addr, len, uf)) {
            return -ENOMEM;
        }
    }
    
    /*
     * Private writable mapping; check memory availability
     */
    // skip this because of three is no file to account
    
    /*
     * Can we just expand an old mapping?
     */
    vma = vma_merge(mm, prev, addr, addr + len, vm_flags, NULL, NULL, 0, NULL, NULL_VM_UFFD_CTX);
    if(vma)
        goto out;
    
    /* Alloc vma struct in kernel */
    vma = kmem_cache_zalloc(vm_area_cachep, GFP_KERNEL);
    if(!vma) {
        error = -ENOMEM;
        goto unacct_error;
    }
    
    vma->vm_mm = mm;
    vma->vm_start = addr;
    vma->vm_end = addr + len;
    vma->vm_flags = vm_flags;
    vma->vm_page_prot = vm_get_page_prot(vm_flags);
    vma->vm_pgoff = pgoff;
    INIT_LIST_HEAD(&vma->anon_vma_chain);
    vma_link(mm, vma, prev, rb_link, rb_parent);
    
out:
    perf_event_mmap(vma);
    vm_stat_account(mm, vm_flags, len >> PAGE_SHIFT);
    vma->vm_flags |= VM_SOFTDIRTY;
    vma_set_page_prot(vma);
    return addr;
    
unmap_and_free_vma:
    vma->vm_file = NULL;
    // punmap_region(mm, vma, prev, vma->vm_start, vma->vm_end);
    charged = 0;
    
free_vma:
    kmem_cache_free(vm_area_cachep, vma);

unacct_error:
    if(charged)
        vm_unacct_memory(charged);
    return error;
}

static void unmap_region(struct mm_struct *mm, struct vm_area_struct *vma, struct vm_area_struct *prev, 
    unsigned long start, unsigned long end) {
    // do nothing for now...
}


