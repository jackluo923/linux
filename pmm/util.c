#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include "pmm.h"

struct pmm_owner* pmm_get_owner_from_pid(struct pmm_store* pstore, pid_t pid) {
  struct list_head *node = NULL;
  struct pmm_owner *owner = NULL;
  
  list_for_each(node, &pstore->owner_list->olist) {
    owner = list_entry(node, struct pmm_owner, olist);
    if(owner->pid == pid) {
      return owner;
    }
  }
  return NULL;
}

// get head element of the list
pid_t pmm_get_head_owner(struct pmm_store* pstore) {
  return pstore->owner_list->pid;
}

// delete from pid list
void pmm_delete_pid_from_list(struct pmm_store* pstore, pid_t pid) {
  struct pmm_owner *todel_powner = NULL;
  struct pmm_owner *pid_owner = NULL;
  struct pmm_owner *new_owner = NULL;
  struct list_head *node = NULL;
  unsigned int att_cnt = 0;
  list_for_each(node, &pstore->owner_list->olist) {
    att_cnt += 1;
    pid_owner = list_entry(node, struct pmm_owner, olist);
    if(pid_owner->pid == pid) {
      todel_powner = pid_owner;
    } else if(new_owner == NULL) { // first owner which is not NULL and not to_del pid
      new_owner = pid_owner;
    }
  }
  if(todel_powner != NULL) {
  	list_del(&todel_powner->olist);
  	kfree(todel_powner);
	att_cnt -= 1;
  }
  if(att_cnt == 0) {
	pstore->owner_list = NULL;
  } else {
    pstore->owner_list = new_owner;
  }
}

// insert element into the pstore's list
void pmm_insert_pid_list(struct pmm_store* pstore, pid_t pid) {
  struct pmm_owner *newowner;
  newowner = kmalloc(sizeof(struct pmm_owner), GFP_KERNEL);
  newowner->pid = pid;
  INIT_LIST_HEAD(&newowner->olist);
  if(pstore->owner_list == NULL) {	  
    pstore->owner_list = newowner;
  } else {
    list_add_tail(&newowner->olist, &pstore->owner_list->olist);
  }
}

int pmm_check_id_conflict(const char* pmmid) {
    int i = 0;
    for(i = 0; i < pdb.store_cnt; i ++) {
        char* existing_pmmid = pdb.stores[i].pmmid;
        if(strcmp(existing_pmmid, pmmid) == 0) {
            // there exists the pmm region with the same ID
            return i;
        }
    }
    // pmm region with the same id does not exist
    return -1;
}

// use the same following scheme in __get_user_pages at mm/gup.c
unsigned long pmm_get_ptn_addr(struct vm_area_struct *vma,
			      unsigned long start, unsigned int gup_flags,
			      unsigned int *page_mask) {
  struct page* page_info = follow_page_mask(vma, start, gup_flags, page_mask);
  unsigned long pfn = page_to_pfn(page_info);
  return pfn;
} 

// Read one byte from kernel page
int pmm_kernel_read_page_byte(char* msg) {
  if(pdb.store_cnt > 0 && pdb.stores[0].cnt > 0) {
    unsigned long pfn = pdb.stores[0].paddr[0];
    unsigned long paddr = pfn * PAGE_SIZE;
    unsigned long kvaddr = (unsigned long) phys_to_virt((phys_addr_t)paddr);
    char c1 = *((char*)kvaddr);
    char c2 = *(((char*)kvaddr) + 1);
    printk("%s : reading from pfn: %lx, paddr: %p, kvaddr: %p, ch1: %c, ch2: %c",
	   msg, pfn, (void*)paddr, (void*)kvaddr, c1, c2);
  }
  return 0;
}
