#ifndef MEMMAN_INCLUDE
#define MEMMAN_INCLUDE

#define MEMMAN_ERROR(c,r) { memman_last_error = c; return r; }

#include <stdlib.h>
#include <errno.h>

#if __cplusplus
extern "C" {
#endif

static int memman_last_error = 0;

struct memman_pool {
        void *base;
        void **head;
        void **head_max;
        size_t block_size; /* In bytes */
        size_t length; /* Total number of blocks */
};

void *memman_pool_end_addr(struct memman_pool *pool);
struct memman_pool *memman_create_pool(size_t block_size, size_t num_blocks);
int memman_free_pool(struct memman_pool *pool);

int memman_last_err(void);

void *memman_alloc(struct memman_pool *pool);
int memman_dealloc(struct memman_pool *pool, void *ptr);
static int memman_valid_addr(struct memman_pool *pool, void *ptr);

int memman_addr_is_free(struct memman_pool *pool, void *ptr);

#if __cplusplus
}
#endif

#endif /* MEMMAN_INCLUDE */

#ifdef MEMMAN_IMPLEMENTATION

/*
 * memman_valid_addr
 * Pool block-pointer sanity checks. Returns 1 if passed, 0 otherwise.
 *
 * @pool Pointer to memman_pool struct.
 * @ptr  Pointer to somewhere in the pool's memory
 */
static inline int memman_valid_addr(struct memman_pool *pool, void *ptr)
{
        if (pool->length == 0 || ptr < pool->base ||
            ptr > pool->base + pool->length * pool->block_size ||
            (ptr - pool->base) % pool->block_size != 0)
                return 0;

        return 1;
}

void inline *memman_pool_end_addr(struct memman_pool *pool)
{
        return pool == NULL ? NULL : (void*)((size_t)pool->base + pool->block_size * pool->length);
}

// Resets and returns last error code (as defined in errno.h)
int memman_last_err(void)
{
        int err = memman_last_error;
        memman_last_error = 0;

        return err;
}

// Returns NULL upon failure.
struct memman_pool *memman_create_pool(size_t block_size, size_t num_blocks)
{
        if (block_size < 1 || block_size > sizeof(void*))
                MEMMAN_ERROR(EINVAL, NULL)

        struct memman_pool *pool = malloc(sizeof(struct memman_pool));

        if (num_blocks > 0) {
                pool->base     = malloc(block_size * num_blocks + 1);
                pool->head     = pool->base;
                pool->head_max = (void*)((size_t)pool->base + block_size);
        } else {
                pool->base     = NULL;
                pool->head     = pool->base;
                pool->head_max = pool->base;
        }

        *pool->head      = pool->head_max;
        pool->block_size = block_size;
        pool->length     = num_blocks;

        return pool;
}

int memman_free_pool(struct memman_pool *pool)
{
        if (pool == NULL)
                MEMMAN_ERROR(EFAULT, 1)

        if (pool->base != NULL)
                free(pool->base);

        free(pool);

        return 0;
}

void *memman_alloc(struct memman_pool *pool)
{
        if (pool->head == NULL || pool->length == 0)
                MEMMAN_ERROR(ENOMEM, NULL)

        void *ptr = pool->head;
        pool->head = *pool->head;

        if (pool->head == NULL)
                goto rtrn_ptr;

        // If we're expanding beyond head_max we have to move head_max forward
        // and write its address to the block head points to, since everything
        // past head_max is heap garbage.
        if (pool->head == pool->head_max) {
                if (pool->head_max != memman_pool_end_addr(pool)) {
                        pool->head_max = (void*)((size_t)pool->head_max + pool->block_size);
                        *pool->head = pool->head_max;
                } else {
                        *pool->head = NULL;
                }
        }

rtrn_ptr:
        return ptr;
}

int memman_dealloc(struct memman_pool *pool, void *ptr)
{
        if (ptr == pool->head || memman_valid_addr(pool, ptr) == 0 ||
            ptr == memman_pool_end_addr(pool))
                MEMMAN_ERROR(EFAULT, 1)

        void *phead = pool->head;

        pool->head = ptr;
        *pool->head = phead;

        return 0;
}

// Checks whether or not an address is part of the linked list of free blocks
int memman_on_free_chain(struct memman_pool *pool, void *ptr)
{
        if (memman_valid_addr(pool, ptr) == 0)
                MEMMAN_ERROR(EFAULT, -1)

        if (ptr == NULL || (void**)ptr > pool->head_max || pool->head == NULL)
                return 0;

        if (ptr == pool->head_max)
                return 1;
        
        void **p = pool->head;
        do {
                if (p == ptr)
                        return 1;
        } while ((p = *p) != NULL && p != pool->head_max);

        return 0;
}

#endif /* MEMMAN_IMPLEMENTATION */