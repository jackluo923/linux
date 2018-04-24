#include <linux/syscalls.h>
#include <linux/huge_mm.h>
#include "pmm.h"
 
#define PHEAP_CREATE 1
#define PHEAP_SHARE 2

/*
 * guid: kernel string
 * If flag == PHEAP_CREATE
 * Else if flag == PHEAP_SHARE: attach an existing pheap
 */
SYSCALL_DEFINE3(pattach, const __user char *, guid, size_t, len, unsigned long, flag) {
  // Step 1: copy id in
  unsigned long ret = 0;
  char pmmid[PMMID_LEN_LIMIT] = {0};
  int i = 0;
  int check = -2;
  
  if(len > PMMID_LEN_LIMIT-1) {
    return -EINVAL;
  }
  ret = copy_from_user(pmmid, guid, len);
  pmmid[len] = '\0'; // add trailing '\0'
  if(ret) {
    return -EFAULT;
  }
  check = pmm_check_id_conflict(pmmid);

  if(check == -2) {
    printk("Panic! Why check is -2? It can be either -1 or other values > 0");
    return -EINVAL;
  }
  if(flag == PHEAP_CREATE) {
    /*********** CREATE **********/
    struct pmm_store* cur_store;
    // create a new pregion for this
    if(check != -1) {
      printk("Now attaching ID: %s, but there is an ID conflict, return.", pmmid);
      return -EINVAL;
    }
    if(current->mm->pstore != NULL) {
      printk("You must detach an existing pstore %s before creating a new one.",
		      current->mm->pstore->pmmid);
      return -EINVAL;
    }
    // printk("Now creating non-existing ID %s", pmmid);
    cur_store = &pdb.stores[pdb.store_cnt];
    /* Set initial pbrk and page count to zero */
    cur_store->cnt = 0;
    // copy pmmid to cur_store.pmmid
    for(i = 0; i < len; i ++) {
      cur_store->pmmid[i] = pmmid[i];
    }
    cur_store->pmmid[len] = '\0'; // trailing '\0'
    /* Insert pstore into mm and pdb */
    current->mm->pstore = cur_store;
    pdb.store_cnt += 1;
    /* Add current process into the owner list */
    pmm_insert_pid_list(cur_store, current->pid);
    current->mm->pstore->owner_list->pbrk_start = MIN_PBRK;
    return ret;
  } else if(flag  == PHEAP_SHARE) {
    /*********** ATTACH **********/
    unsigned long oldpbrk = MIN_PBRK;
    unsigned long region_len = 0;
    struct pmm_owner* owner = NULL;
    struct vm_area_struct *target_vma = NULL;

    LIST_HEAD(uf);
    if(check == -1) {
      printk("Error when attaching ID: %s, but there is no existing store with this ID, return.", pmmid);
      return -EINVAL;
    }
    if(current->mm->pstore != NULL) {
      printk("Error when attaching ID: %s, please detach current pstore %s first.", pmmid, current->mm->pstore->pmmid);
      return -EINVAL;
    }
    /* TODO: permission checking */
    
    /* Load vma into the kernel: get pbrk, then call do_pbrk() */
    // PTE: 9, POFFSET: 12, PMD: 9, HPAGE_PMD_SIZE == 1 << HPAGE_PMD_SHIFT == 1 << 21
    region_len = pdb.stores[check].cnt * PAGE_SIZE;
    printk("Now attaching an existing ID %s with check value %d, size: %lx", pmmid, check, region_len);
    
    if(down_write_killable(&current->mm->mmap_sem)) {
      return -EINTR;
    }
    if(do_pbrk(current->mm, oldpbrk, region_len, &uf, &target_vma) < 0) {
      up_write(&current->mm->mmap_sem);
      return -ENOMEM;
    }
    /* populate. No need to record, because it is already in the pstore */
    current->mm->pstore = &pdb.stores[check];
    pmm_insert_pid_list(current->mm->pstore, current->pid);
    owner = pmm_get_owner_from_pid(current->mm->pstore, current->pid);
    owner->pbrk_start = MIN_PBRK;
    up_write(&current->mm->mmap_sem);
    mm_populate(oldpbrk, region_len);
    return ret;
  }
  return ret;
}

SYSCALL_DEFINE0(pdetach) {
  /* Unload vma from the kernel, resembles punmap code */
  unsigned long start = MIN_PBRK;
  unsigned long cur_pbrk = 0;
  unsigned long len = 0;
  struct pmm_owner *powner = pmm_get_owner_from_pid(current->mm->pstore, current->pid);

  if(current->mm->pstore == NULL) {
    printk("Error: you are calling detach without attaching a pstore.");
    return -EINVAL;
  }
  powner = pmm_get_owner_from_pid(current->mm->pstore, current->pid);
  if(powner == NULL) {
    printk("Error: you are calling on not attached process.");
    return -EINVAL;
  }
  start = powner->pbrk_start;
  cur_pbrk = current->mm->pstore->pbrk;
  len = (cur_pbrk - start);
  vm_munmap(start, len);
  pmm_delete_pid_from_list(current->mm->pstore, current->pid);
  current->mm->pstore = NULL;
  return 0;
}

SYSCALL_DEFINE1(pchmod, unsigned long, mode) {
  return 0;
}
