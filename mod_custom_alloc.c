#include <stdio.h>
#include <stddef.h>
#include <unistd.h>
#include <string.h>
#include <limits.h> // For SIZE_MAX
#include <stdint.h> // For uint32_t etc.
#include <stdlib.h> // For the real malloc/free used by the Pool

/*  SECTION 1: MODIFIED(SENTINEL) GENERAL-PURPOSE ALLOCATOR
 *******************************************************************************
 *  Features:
 *  - Guard Bands (Canaries) to detect buffer overflows.
 *  - Magic Numbers to detect double-frees or invalid pointers.
 *  - Memory Stomping on free to make use-after-free bugs more obvious.
 *  - A Fail-Safe API for robust array allocation.
 ******************************************************************************/

#define MEMORY_POOL_SIZE (1024 * 1024) // 1MB main pool
#define ALIGNMENT 8
#define ALIGN(size) (((size) + (ALIGNMENT - 1)) & ~(ALIGNMENT - 1))

// --- Sentinel Feature Defines ---
#define SENTINEL_MAGIC 0xDEADBEEF  // Magic number to validate allocated blocks
#define CANARY_VALUE 0xAFAFAFAF   // Value placed after user data
#define FREED_PATTERN 0xCC         // Pattern to write over freed memory

typedef struct FreeBlockHeader {
    size_t blockSize;
    struct FreeBlockHeader* next;
} FreeBlockHeader;

typedef struct AllocatedBlockHeader {
    size_t blockSize;
    uint32_t magic; // For double-free detection
} AllocatedBlockHeader;

static unsigned char g_memoryPool[MEMORY_POOL_SIZE];
static FreeBlockHeader* g_freeListHead = NULL;

void initialize_sentinel_allocator() {
    g_freeListHead = (FreeBlockHeader*)g_memoryPool;
    g_freeListHead->blockSize = MEMORY_POOL_SIZE;
    g_freeListHead->next = NULL;
}

// --- FORWARD DECLARATIONS ---
void sentinel_free(void* ptr);
// THIS IS THE FIX: Declare sentinel_malloc before it is used.
void* sentinel_malloc(size_t size); 

// The Fail-Safe array allocation function
void* sentinel_malloc_array(size_t num_items, size_t item_size) {
    // FAIL-SAFE CHECK: Integer overflow protection
    if (item_size > 0 && num_items > SIZE_MAX / item_size) {
        fprintf(stderr, "SENTINEL ERROR: Integer overflow in array allocation request.\n");
        return NULL;
    }
    // Now the compiler knows the correct return type of sentinel_malloc
    return sentinel_malloc(num_items * item_size);
}

void* sentinel_malloc(size_t size) {
    if (g_freeListHead == NULL) {
        initialize_sentinel_allocator();
    }
    if (size == 0) return NULL;

    size_t alignedSize = ALIGN(size);
    // Total size needs space for the header AND the canary at the end
    size_t totalBlockSize = ALIGN(sizeof(AllocatedBlockHeader)) + alignedSize + ALIGN(sizeof(uint32_t));

    FreeBlockHeader* prev = NULL;
    FreeBlockHeader* curr = g_freeListHead;
    while (curr != NULL && curr->blockSize < totalBlockSize) {
        prev = curr;
        curr = curr->next;
    }

    if (curr == NULL) {
        fprintf(stderr, "SENTINEL ERROR: Out of memory.\n");
        return NULL;
    }

    // Remove block from free list
    if (prev) {
        prev->next = curr->next;
    } else {
        g_freeListHead = curr->next;
    }

    AllocatedBlockHeader* allocHeader = (AllocatedBlockHeader*)curr;
    allocHeader->blockSize = totalBlockSize;
    allocHeader->magic = SENTINEL_MAGIC;
    
    void* userData = (void*)((unsigned char*)allocHeader + ALIGN(sizeof(AllocatedBlockHeader)));

    uint32_t* canary_ptr = (uint32_t*)((unsigned char*)userData + alignedSize);
    *canary_ptr = CANARY_VALUE;

    return userData;
}

void sentinel_free(void* ptr) {
    if (ptr == NULL) return;

    AllocatedBlockHeader* header = (AllocatedBlockHeader*)((unsigned char*)ptr - ALIGN(sizeof(AllocatedBlockHeader)));

    // SENTINEL CHECK 1: Double-free or invalid pointer
    if (header->magic != SENTINEL_MAGIC) {
        fprintf(stderr, "SENTINEL ERROR: Attempt to free invalid pointer or double-free detected!\n");
        return;
    }
    
    size_t alignedUserDataSize = header->blockSize - ALIGN(sizeof(AllocatedBlockHeader)) - ALIGN(sizeof(uint32_t));
    
    // SENTINEL CHECK 2: Canary for buffer overflow
    uint32_t* canary_ptr = (uint32_t*)((unsigned char*)ptr + alignedUserDataSize);
    if (*canary_ptr != CANARY_VALUE) {
        fprintf(stderr, "SENTINEL ERROR: Buffer overflow detected! Canary was smashed.\n");
    }
    
    header->magic = 0;
    memset(ptr, FREED_PATTERN, alignedUserDataSize);

    FreeBlockHeader* freeBlock = (FreeBlockHeader*)header;
    freeBlock->blockSize = header->blockSize;
    freeBlock->next = g_freeListHead;
    g_freeListHead = freeBlock;
}


/*******************************************************************************
 *
 *  SECTION 2: MINIMALIST BITMAP POOL
 *
 *******************************************************************************
 *  Features:
 *  - Uses a bitmap for metadata, reducing overhead to ~1 bit per object.
 *  - Ideal for allocating many small objects of the same size efficiently.
 ******************************************************************************/

typedef struct {
    unsigned char* memory_pool;
    uint32_t* bitmap;
    size_t num_blocks;
    size_t block_size;
    size_t bitmap_size_in_words;
} BitmapPool;

BitmapPool* pool_create(size_t block_size, size_t block_count) {
    BitmapPool* pool = malloc(sizeof(BitmapPool));
    if (!pool) return NULL;

    pool->block_size = ALIGN(block_size);
    pool->num_blocks = block_count;
    pool->memory_pool = malloc(pool->num_blocks * pool->block_size);
    pool->bitmap_size_in_words = (pool->num_blocks + 31) / 32;
    pool->bitmap = calloc(pool->bitmap_size_in_words, sizeof(uint32_t));

    if (!pool->memory_pool || !pool->bitmap) {
        free(pool->memory_pool);
        free(pool->bitmap);
        free(pool);
        return NULL;
    }
    return pool;
}

void pool_destroy(BitmapPool* pool) {
    free(pool->memory_pool);
    free(pool->bitmap);
    free(pool);
}

void* pool_alloc(BitmapPool* pool) {
    for (size_t i = 0; i < pool->bitmap_size_in_words; ++i) {
        if (pool->bitmap[i] != 0xFFFFFFFF) {
            for (int j = 0; j < 32; ++j) {
                if (!((pool->bitmap[i] >> j) & 1)) {
                    pool->bitmap[i] |= (1 << j);
                    size_t block_index = i * 32 + j;
                    if (block_index < pool->num_blocks) {
                        return pool->memory_pool + (block_index * pool->block_size);
                    }
                }
            }
        }
    }
    return NULL;
}

void pool_free(BitmapPool* pool, void* ptr) {
    if (!ptr || ptr < (void*)pool->memory_pool || ptr >= (void*)(pool->memory_pool + (pool->num_blocks * pool->block_size))) {
        fprintf(stderr, "POOL ERROR: Pointer is null or does not belong to this pool.\n");
        return;
    }
    size_t block_index = ((unsigned char*)ptr - pool->memory_pool) / pool->block_size;
    size_t word_index = block_index / 32;
    int bit_index = block_index % 32;
    pool->bitmap[word_index] &= ~(1 << bit_index);
}


/*******************************************************************************
 *  SECTION 3: DEMONSTRATION
 ******************************************************************************/

int main() {
    printf("--- DEMONSTRATING THE SENTINEL ALLOCATOR SUITE ---\n\n");

    // --- 1. Sentinel Allocator Demo ---
    printf("--- 1. Sentinel General-Purpose Allocator Demo ---\n");
    printf("Allocating 32 bytes...\n");
    char* ptr = sentinel_malloc(32);
    strcpy(ptr, "This is a test string.");
    printf("String content: %s\n", ptr);

    printf("\nTEST: Simulating buffer overflow...\n");
    ptr[40] = 'X'; 
    printf("Freeing the pointer...\n");
    sentinel_free(ptr);

    printf("\nTEST: Simulating double-free...\n");
    char* ptr2 = sentinel_malloc(16);
    sentinel_free(ptr2);
    printf("Attempting to free the same pointer again...\n");
    sentinel_free(ptr2);

    // --- 2. Fail-Safe Array Allocator Demo ---
    printf("\n--- 2. Fail-Safe Array Allocator Demo ---\n");
    printf("Attempting to allocate a huge array that would overflow...\n");
    void* huge_array = sentinel_malloc_array(SIZE_MAX / 2, 8);
    if (huge_array == NULL) {
        printf("SUCCESS: The fail-safe check correctly prevented the allocation.\n");
    }

    // --- 3. Minimalist Bitmap Pool Demo ---
    printf("\n--- 3. Minimalist Bitmap Pool Demo ---\n");
    printf("Creating a pool for 128 objects of 64 bytes each.\n");
    BitmapPool* my_pool = pool_create(64, 128);
    
    if(my_pool) {
        void* obj1 = pool_alloc(my_pool);
        pool_free(my_pool, obj1);
        void* obj2 = pool_alloc(my_pool);
        printf("Pool allocated one object, freed it, and allocated another at the same address: %p\n", obj2);
        pool_destroy(my_pool);
    }
    
    printf("\n--- DEMO COMPLETE ---\n");
    return 0;
}
