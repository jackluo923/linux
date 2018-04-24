/* SPDX-License-Identifier: GPL-2.0 */
#pragma once
#include <linux/types.h>
#include <linux/list.h>
// #define MIN_PBRK 0x2a0002000000UL
#define MIN_PBRK 0x80000000UL
#define MAX_PMM_SIZE 20 // 20 pages, for now we have 16 x 4k = 64k
#define PMM_COUNT_LIMIT 16
#define PMMID_LEN_LIMIT 20

// helper functions
struct pmm_owner* pmm_get_owner_from_pid(struct pmm_store* pstore, pid_t pid);
void pmm_delete_pid_from_list(struct pmm_store* pstore, pid_t pid);
pid_t pmm_get_head_owner(struct pmm_store* pstore);
void pmm_insert_pid_list(struct pmm_store* pstore, pid_t pid);
void extend_process_pbrk(struct task_struct *task, unsigned long oldpbrk,
			 unsigned long newpbrk);
int pmm_check_id_conflict(const char* pmmid);
unsigned long
arch_get_unmapped_area(struct file *filp, unsigned long addr,
		unsigned long len, unsigned long pgoff, unsigned long flags); 

unsigned long pmm_get_ptn_addr(struct vm_area_struct *vma,
			      unsigned long start, unsigned int gup_flags,
			      unsigned int *page_mask);

int pmm_kernel_read_page_byte(char* msg);
int pmm_nonempty(void);
int do_pbrk(struct mm_struct *mm, unsigned long addr, unsigned long request, struct list_head* uf, struct vm_area_struct **target_vma);

// Design
// Store: a list of physical pages
// Each physical page: attach a struct, which pmm it belongs to

struct pmm_owner {
  pid_t pid;
  unsigned long pbrk_start;
  struct list_head olist;
};

struct pmm_store {
  char pmmid[PMMID_LEN_LIMIT];
  int cnt; /* number of pmm pages */
  unsigned long paddr[MAX_PMM_SIZE];
  unsigned long mode;
  unsigned long pbrk;
  struct pmm_owner *owner_list; // this field should be volatile!
};

// Overall pmm database in kernel
struct pmm_database {
  struct pmm_store stores[PMM_COUNT_LIMIT];
  int store_cnt;
};

extern struct pmm_database pdb;
