// SPDX-License-Identifier: BSD-3-Clause

#include "osmem.h"


#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>

#include <string.h>
#include "block_meta.h"

#include "printf.h"

#define ALIGNMENT 8
#define ALIGN(size) (((size) + (ALIGNMENT - 1)) & ~(ALIGNMENT - 1))

#define META_SIZE (ALIGN(sizeof(struct block_meta)))
#define MMAP_THRESHOLD 131072  // 128 KB

struct block_meta *global_base;
int global_heap_init;

struct block_meta *alloc_block_mmap(size_t size)
{
	struct block_meta *block;

	block = mmap(NULL, size + META_SIZE, PROT_READ | PROT_WRITE,
				MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	DIE(block == MAP_FAILED, "mmap failed!\n");
	block->status = STATUS_MAPPED;
	block->size = size;
	block->next = NULL;
	block->prev = NULL;
	return block;
}

struct block_meta *alloc_block_sbrk(size_t size)
{
	struct block_meta *block;

	block = sbrk(size + META_SIZE);
	DIE(block == (void *)-1, "sbrk failed!\n");
	block->status = STATUS_ALLOC;
	block->size = size;
	block->next = NULL;
	block->prev = NULL;
	return block;
}

struct block_meta *get_block(void *ptr)
{
	return (struct block_meta *)ptr - 1;
}

struct block_meta *find_best_fit(struct block_meta **last, size_t size)
{
	struct block_meta *chosen = NULL, *curr = global_base;

	while (curr) {
		*last = curr;
		if (curr->status == STATUS_FREE && curr->size >= size) {
			if (chosen == NULL)
				chosen = curr;
			else if (curr->size - size < chosen->size - size)
				chosen = curr;
		}
		curr = curr->next;
	}
	return chosen;
}

void add_block(struct block_meta *new_block)
{
	if (!global_base) {
		global_base = new_block;
	} else {
		struct block_meta *ptr = global_base;

		while (ptr->next)
			ptr = ptr->next;
		ptr->next = new_block;
		new_block->prev = ptr;
	}
}

void split_block(struct block_meta *block, size_t size)
{
	struct block_meta *split_block =
		(struct block_meta *)((char *)block + ALIGN(size) + META_SIZE);
	split_block->size = block->size - ALIGN(size) - META_SIZE;
	split_block->next = block->next;
	split_block->prev = block;
	split_block->status = STATUS_FREE;
	if (block->next)
		block->next->prev = split_block;
	block->size = ALIGN(size);
	block->next = split_block;
	block->status = STATUS_ALLOC;
}

void coalesce_blocks(void)
{
	struct block_meta *curr = global_base, *next = global_base->next;

	while (curr && next) {
		if (curr->status == STATUS_FREE && next->status == STATUS_FREE) {
			struct block_meta *afterNext = next->next;

			curr->next = afterNext;
			curr->size += next->size + META_SIZE;
			if (afterNext)
				afterNext->prev = curr;
			next = afterNext;
		} else {
			curr = curr->next;
			if (!curr)
				break;
			next = curr->next;
		}
	}
}

void *os_malloc(size_t size)
{
	if (size == 0)
		return NULL;
	if (ALIGN(size) + META_SIZE >= MMAP_THRESHOLD) {
		struct block_meta *new_block = alloc_block_mmap(ALIGN(size));

		add_block(new_block);
		return (new_block + 1);
	}
	// Preallocate
	if (!global_heap_init && ALIGN(size) + META_SIZE < MMAP_THRESHOLD) {
		struct block_meta *block = sbrk(0);
		void *request = sbrk(MMAP_THRESHOLD);

		DIE(request == (void *)-1, "sbrk failed!\n");
		block->size = MMAP_THRESHOLD - META_SIZE;
		block->next = NULL;
		block->prev = NULL;
		block->status = STATUS_FREE;
		add_block(block);
		global_heap_init = 1;
	}
	if (!global_base) {
		struct block_meta *new_block = alloc_block_sbrk(ALIGN(size));

		if (!new_block)
			return NULL;
		global_base = new_block;
		return (new_block + 1);
	}
	coalesce_blocks();
	struct block_meta *last = global_base;

	struct block_meta *free_block = find_best_fit(&last, ALIGN(size));

	if (!free_block) {
	// Failed to find free block.
	// If found block is last, then expand.
		if (last->status == STATUS_FREE) {
			void *request = sbrk(ALIGN(size - last->size));

			DIE(request == (void *)-1, "sbrk failed!\n");
			last->size = ALIGN(size);
			last->status = STATUS_ALLOC;
			return (last + 1);
		}
		struct block_meta *new_block = alloc_block_sbrk(ALIGN(size));

		if (!new_block)
			return NULL;
		add_block(new_block);
		return (new_block + 1);
	}
	if (free_block->size > ALIGN(size) + META_SIZE)
		split_block(free_block, size);
	free_block->status = STATUS_ALLOC;
	return (free_block + 1);
}

void os_free(void *ptr)
{
	if (!ptr || !global_base)
		return;
	struct block_meta *block = get_block(ptr);

	DIE(block->status == STATUS_FREE, "double free detected\n");
	if (block->status == STATUS_MAPPED) {
		if (global_base == block) {
			global_base = block->next;
			if (global_base)
				global_base->prev = NULL;
		} else {
			struct block_meta *prev_block = block->prev;

			struct block_meta *next_block = block->next;

			prev_block->next = next_block;
			if (next_block)
				next_block->prev = prev_block;
		}
		int ret = munmap(block, block->size + META_SIZE);

		DIE(ret == -1, "munmap failed\n");
		return;
	}
	block->status = STATUS_FREE;
}

void *os_calloc(size_t nmemb, size_t size)
{
	if (nmemb == 0 || size == 0)
		return NULL;
	int pageSize = getpagesize();

	size *= nmemb;
	if (ALIGN(size) + META_SIZE >= (unsigned long)pageSize) {
		struct block_meta *new_block = alloc_block_mmap(ALIGN(size));

		add_block(new_block);
		memset(new_block + 1, 0, ALIGN(size));
		return (new_block + 1);
	}
	// Preallocate
	if (!global_heap_init && ALIGN(size) + META_SIZE < (unsigned long) pageSize) {
		struct block_meta *block = sbrk(0);

		void *request = sbrk(MMAP_THRESHOLD);

		DIE(request == (void *)-1, "sbrk failed!\n");
		block->size = MMAP_THRESHOLD - META_SIZE;
		block->next = NULL;
		block->prev = NULL;
		block->status = STATUS_FREE;
		add_block(block);
		memset(block + 1, 0, MMAP_THRESHOLD - META_SIZE);
		global_heap_init = 1;
	}
	if (!global_base) {
		struct block_meta *new_block = alloc_block_sbrk(ALIGN(size));

		if (!new_block)
			return NULL;
		global_base = new_block;
		memset(new_block + 1, 0, ALIGN(size));
		return (new_block + 1);
	}
	coalesce_blocks();
	struct block_meta *last = global_base;

	struct block_meta *free_block = find_best_fit(&last, ALIGN(size));

	if (!free_block) {
		// Failed to find free block.
		// If found block is last, then expand.
		if (last->status == STATUS_FREE) {
			void *request = sbrk(ALIGN(size - last->size));

			DIE(request == (void *)-1, "sbrk failed!\n");
			last->size = ALIGN(size);
			last->status = STATUS_ALLOC;
			memset(last + 1, 0, ALIGN(size));
			return (last + 1);
		}
		struct block_meta *new_block = alloc_block_sbrk(ALIGN(size));

		if (!new_block)
			return NULL;
		add_block(new_block);
		memset(new_block + 1, 0, ALIGN(size));
		return (new_block + 1);
	}
	if (free_block->size > ALIGN(size) + META_SIZE)
		split_block(free_block, size);
	free_block->status = STATUS_ALLOC;
	memset(free_block + 1, 0, ALIGN(size));
	return (free_block + 1);
}

void *os_realloc(void *ptr, size_t size)
{
	if (!ptr)
		return os_malloc(size);
	if (!size) {
		os_free(ptr);
		return NULL;
	}
	struct block_meta *block = get_block(ptr);

	if (block->status == STATUS_FREE)
		return NULL;
	if (block->size == ALIGN(size))
		return ptr;
	if (block->status == STATUS_MAPPED) {
		void *new_ptr = os_malloc(size);

		if (!new_ptr)
			return NULL;
		memcpy(new_ptr, ptr, ALIGN(size));
		os_free(ptr);
		return new_ptr;
	}
	if (block->size > ALIGN(size) + META_SIZE) {
		split_block(block, size);
		return ptr;
	}
	if (block->size > ALIGN(size))
		return ptr;
	if (!block->next) {
		size_t size_diff = ALIGN(size) - block->size;
		void *request = sbrk(ALIGN(size_diff));

		DIE(request == (void *)-1, "sbrk failed!\n");
		block->size = ALIGN(size);
		return ptr;
	}
	struct block_meta *next = block->next;

	while (next && next->status == STATUS_FREE) {
		block->size += next->size + META_SIZE;
		block->next = next->next;
		if (next->next)
			next->next->prev = block;
		if (block->size == ALIGN(size))
			return ptr;
		if (block->size > ALIGN(size) + META_SIZE) {
			split_block(block, size);
			return ptr;
		}
		next = block->next;
	}
	if (block->size > ALIGN(size))
		return ptr;
	void *new_ptr = os_malloc(size);

	if (!new_ptr)
		return NULL;
	memcpy(new_ptr, ptr, block->size);
	os_free(ptr);
	return new_ptr;
}
