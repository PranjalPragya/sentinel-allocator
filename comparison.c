#include <stdio.h>
#include <stddef.h>
#include <string.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>

/*******************************************************************************
 *
 *                  MODIFIED CUSTOM ALLOCATOR SHOWDOWN
 *                      
 *
 *  This single file contains two fully independent allocator implementations:
 *  1. A "Normal" Allocator: Based on the original functional but naive code.
 *  2. A "Modified/Sentinel" Allocator: The enhanced, robust, and debug-focused version.
 *
 *  The main() function at the bottom runs a comparative demonstration to
 *  highlight the critical differences in their behavior when faced with
 *  common programming errors.
 *
 *******************************************************************************


#define ALIGNMENT 8
#define ALIGN(size) (((size) + (ALIGNMENT - 1)) & ~(ALIGNMENT - 1))
#define MEMORY_POOL_SIZE (1024 * 1024)

/*******************************************************************************
 *                IMPLEMENTATION 1: THE SENTINEL ALLOCATOR SUITE
 *                (Robust, Debug-Focused, Fail-Safe)
 ******************************************************************************/

#define SENTINEL_MAGIC 0xDEADBEEF
#define CANARY_VALUE 0xAFAFAFAF
#define FREED_PATTERN 0xCC

typedef struct SentinelFreeBlock { size_t blockSize; struct SentinelFreeBlock* next; } SentinelFreeBlock;
typedef struct SentinelAllocatedBlock { size_t blockSize; uint32_t magic; } SentinelAllocatedBlock;

static unsigned char g_sentinel_memoryPool[MEMORY_POOL_SIZE];
static SentinelFreeBlock* g_sentinel_freeListHead = NULL;

void sentinel_initialize()
{
    g_sentinel_freeListHead = (SentinelFreeBlock*)g_sentinel_memoryPool;
    g_sentinel_freeListHead->blockSize = MEMORY_POOL_SIZE;
    g_sentinel_freeListHead->next = NULL;
}

void* sentinel_malloc(size_t size)
{
    if (!g_sentinel_freeListHead) { sentinel_initialize(); }
    if (size == 0) { return NULL; }

    size_t alignedSize = ALIGN(size);
    // Sentinel adds space for its header and a canary at the end
    size_t totalBlockSize = ALIGN(sizeof(SentinelAllocatedBlock)) + alignedSize + ALIGN(sizeof(uint32_t));

    SentinelFreeBlock* prev = NULL;
    SentinelFreeBlock* curr = g_sentinel_freeListHead;
    while (curr != NULL && curr->blockSize < totalBlockSize)
    {
        prev = curr;
        curr = curr->next;
    }

    if (curr == NULL) { fprintf(stderr, "SENTINEL ERROR: Out of memory.\n"); return NULL; }

    if (prev) { prev->next = curr->next; } else { g_sentinel_freeListHead = curr->next; }

    SentinelAllocatedBlock* header = (SentinelAllocatedBlock*)curr;
    header->blockSize = totalBlockSize;
    header->magic = SENTINEL_MAGIC; // Set the magic number

    void* userData = (void*)((unsigned char*)header + ALIGN(sizeof(SentinelAllocatedBlock)));
    uint32_t* canary = (uint32_t*)((unsigned char*)userData + alignedSize);
    *canary = CANARY_VALUE; // Place the canary

    return userData;
}

void sentinel_free(void* ptr)
{
    if (!ptr) return;
    SentinelAllocatedBlock* header = (SentinelAllocatedBlock*)((unsigned char*)ptr - ALIGN(sizeof(SentinelAllocatedBlock)));
    
    // Check 1: Double-free or invalid pointer
    if (header->magic != SENTINEL_MAGIC) { fprintf(stderr, "SENTINEL ERROR: Double-free or invalid pointer detected!\n"); return; }

    size_t userDataSize = header->blockSize - ALIGN(sizeof(SentinelAllocatedBlock)) - ALIGN(sizeof(uint32_t));
    uint32_t* canary = (uint32_t*)((unsigned char*)ptr + userDataSize);
    
    // Check 2: Buffer overflow
    if (*canary != CANARY_VALUE) { fprintf(stderr, "SENTINEL ERROR: Buffer overflow detected! Canary was smashed.\n"); }

    header->magic = 0; // Invalidate the magic number
    memset(ptr, FREED_PATTERN, userDataSize); // Stomp the memory

    SentinelFreeBlock* freeBlock = (SentinelFreeBlock*)header;
    freeBlock->blockSize = header->blockSize;
    freeBlock->next = g_sentinel_freeListHead;
    g_sentinel_freeListHead = freeBlock;
}

void* sentinel_malloc_array(size_t n, size_t s)
{
    // Check 3: Integer overflow
    if (s > 0 && n > SIZE_MAX / s) { fprintf(stderr, "SENTINEL ERROR: Integer overflow in array allocation request.\n"); return NULL; }
    return sentinel_malloc(n * s);
}


/*******************************************************************************
 *                      IMPLEMENTATION 2: THE NORMAL ALLOCATOR
 *               (Based on the original, with unsafe behaviors)
 ******************************************************************************/

typedef struct NormalFreeBlock { size_t blockSize; struct NormalFreeBlock* next; } NormalFreeBlock;
typedef struct NormalAllocatedBlock { size_t blockSize; } NormalAllocatedBlock;

static unsigned char g_normal_memoryPool[MEMORY_POOL_SIZE];
static NormalFreeBlock* g_normal_freeListHead = NULL;

void normal_initialize()
{
    g_normal_freeListHead = (NormalFreeBlock*)g_normal_memoryPool;
    g_normal_freeListHead->blockSize = MEMORY_POOL_SIZE;
    g_normal_freeListHead->next = NULL;
}

void* normal_malloc(size_t size)
{
    if (!g_normal_freeListHead) { normal_initialize(); }
    if (size == 0) { return NULL; }

    
    size_t totalBlockSize = ALIGN(size) + sizeof(NormalAllocatedBlock);
    NormalFreeBlock* prev = NULL;
    NormalFreeBlock* curr = g_normal_freeListHead;

    while (curr != NULL && curr->blockSize < totalBlockSize)
    {
        prev = curr;
        curr = curr->next;
    }

    if (curr == NULL) { return NULL; }
    if (prev) { prev->next = curr->next; } else { g_normal_freeListHead = curr->next; }

    NormalAllocatedBlock* header = (NormalAllocatedBlock*)curr;
    header->blockSize = totalBlockSize;
    return (void*)((unsigned char*)header + sizeof(NormalAllocatedBlock));
}

void normal_free(void* ptr)
{
    
    if (!ptr) return;
    NormalAllocatedBlock* header = (NormalAllocatedBlock*)((unsigned char*)ptr - sizeof(NormalAllocatedBlock));
    NormalFreeBlock* freeBlock = (NormalFreeBlock*)header;
    freeBlock->next = g_normal_freeListHead;
    g_normal_freeListHead = freeBlock;
}

void* normal_malloc_array(size_t n, size_t s)
{
    // Performs a raw, unsafe multiplication
    return normal_malloc(n * s);
}


/*******************************************************************************
 *                           DEMONSTRATION LOGIC
 ******************************************************************************/

int main()
{
    printf("\n=========================================================\n");
    printf("     CUSTOM ALLOCATOR SHOWDOWN: NORMAL vs. MODIFIED/SENTINEL\n");
    printf("=========================================================\n\n");

    // --- TEST 1: BUFFER OVERFLOW ---
    printf("---[ Test 1: Buffer Overflow ]--------------------------\n");
    printf(">>> Running on NORMAL Allocator:\n");
    char* normal_ptr1 = normal_malloc(32);
    memset(normal_ptr1, 'A', 40); // Overflow by 8 bytes
    normal_free(normal_ptr1);
    printf("    RESULT: No error reported. The heap is now silently corrupted.\n\n");

    printf(">>> Running on SENTINEL Allocator:\n");
    char* sentinel_ptr1 = sentinel_malloc(32);
    memset(sentinel_ptr1, 'A', 40); // Overflow by 8 bytes
    sentinel_free(sentinel_ptr1);
    printf("    RESULT: The error was successfully detected and reported.\n");
    printf("--------------------------------------------------------\n\n");


    // --- TEST 2: DOUBLE FREE ---
    printf("---[ Test 2: Double Free ]------------------------------\n");
    printf(">>> Running on NORMAL Allocator:\n");
    char* normal_ptr2 = normal_malloc(16);
    normal_free(normal_ptr2);
    normal_free(normal_ptr2); // The incorrect second free
    printf("    RESULT: No error reported. The free list is now corrupted.\n\n");

    printf(">>> Running on SENTINEL Allocator:\n");
    char* sentinel_ptr2 = sentinel_malloc(16);
    sentinel_free(sentinel_ptr2);
    sentinel_free(sentinel_ptr2); // The incorrect second free
    printf("    RESULT: The error was successfully detected and reported.\n");
    printf("--------------------------------------------------------\n\n");


    // --- TEST 3: INTEGER OVERFLOW IN ARRAY ALLOCATION ---
    printf("---[ Test 3: Integer Overflow ]-------------------------\n");
    printf(">>> Running on NORMAL Allocator:\n");
    void* normal_ptr3 = normal_malloc_array(SIZE_MAX / 2, 4);
    if (normal_ptr3 != NULL)
    {
        printf("    RESULT: DANGEROUSLY returned a non-NULL pointer.\n\n");
    }
    else
    {
        printf("    RESULT: Allocation failed (as expected), but without a clear error.\n\n");
    }

    printf(">>> Running on Modified/SENTINEl Allocator:\n");
    void* sentinel_ptr3 = sentinel_malloc_array(SIZE_MAX / 2, 4);
    if (sentinel_ptr3 == NULL)
    {
        printf("    RESULT: SAFELY returned NULL after detecting the overflow.\n");
    }
    printf("--------------------------------------------------------\n\n");

    return 0;
}
