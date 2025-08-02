#include <stdio.h>
#include <stddef.h>
#include <unistd.h>
#include <string.h>

// Defines the total size of the memory pool managed by the allocator.
#define MEMORY_POOL_SIZE (1024 * 1024) // 1MB

// Defines the minimum size of a block that can be returned to the user.
#define MIN_BLOCK_SIZE sizeof(FreeBlockHeader)

// Alignment requirement for allocated memory (must be a power of 2).
// A common alignment is 8 or 16 bytes.
#define ALIGNMENT 8

// Macro to align a size to the nearest alignment boundary.
#define ALIGN(size) (((size) + (ALIGNMENT - 1)) & ~(ALIGNMENT - 1))

/**
 * @brief Represents the header of a free memory block.
 *
 * This structure is placed at the beginning of each free block of memory
 * and is used to form a linked list of free blocks.
 */
typedef struct FreeBlockHeader {
    size_t blockSize;             // Size of the free block (including the header).
    struct FreeBlockHeader* next; // Pointer to the next free block in the list.
} FreeBlockHeader;

/**
 * @brief Represents the header of an allocated memory block.
 *
 * This structure is placed at the beginning of each allocated block of memory.
 * It stores the size of the block, which is needed when the block is freed.
 */
typedef struct AllocatedBlockHeader {
    size_t blockSize; // Size of the allocated block (including the header).
} AllocatedBlockHeader;

// The global memory pool from which memory will be allocated.
static unsigned char memoryPool[MEMORY_POOL_SIZE];

// Pointer to the head of the free list.
static FreeBlockHeader* freeListHead = NULL;

// Statistics to track memory usage.
static size_t totalAllocatedMemory = 0;
static size_t totalFreeMemory = 0;
static size_t allocationCount = 0;
static size_t freeCount = 0;

/**
 * @brief Initializes the custom memory allocator.
 *
 * This function sets up the initial free block in the memory pool.
 * It should be called once before any other allocator functions are used.
 */
void initializeAllocator() {
    // The entire memory pool is initially one large free block.
    freeListHead = (FreeBlockHeader*)memoryPool;
    freeListHead->blockSize = MEMORY_POOL_SIZE;
    freeListHead->next = NULL;
    totalFreeMemory = MEMORY_POOL_SIZE;
}

/**
 * @brief Allocates a block of memory of the specified size.
 *
 * @param size The number of bytes to allocate.
 * @return A pointer to the allocated memory, or NULL if the allocation fails.
 */
void* customMalloc(size_t size) {
    if (size == 0) {
        return NULL;
    }

    // Align the requested size to ensure proper memory alignment.
    size_t alignedSize = ALIGN(size);
    // The total size needed for the block includes the header for an allocated block.
    size_t totalBlockSize = alignedSize + sizeof(AllocatedBlockHeader);

    FreeBlockHeader* previousBlock = NULL;
    FreeBlockHeader* currentBlock = freeListHead;

    // Traverse the free list to find a suitable block (first-fit).
    while (currentBlock != NULL) {
        if (currentBlock->blockSize >= totalBlockSize) {
            // Found a suitable block.
            break;
        }
        previousBlock = currentBlock;
        currentBlock = currentBlock->next;
    }

    if (currentBlock == NULL) {
        // No suitable block found in the free list.
        fprintf(stderr, "customMalloc: Out of memory\n");
        return NULL;
    }

    // Determine if the found block should be split.
    if (currentBlock->blockSize >= totalBlockSize + MIN_BLOCK_SIZE) {
        // The block is large enough to be split.
        // Create a new free block from the remaining space.
        FreeBlockHeader* newFreeBlock = (FreeBlockHeader*)((unsigned char*)currentBlock + totalBlockSize);
        newFreeBlock->blockSize = currentBlock->blockSize - totalBlockSize;
        newFreeBlock->next = currentBlock->next;

        // The current block becomes the allocated block.
        currentBlock->blockSize = totalBlockSize;

        if (previousBlock != NULL) {
            previousBlock->next = newFreeBlock;
        } else {
            // The head of the free list is being allocated.
            freeListHead = newFreeBlock;
        }
    } else {
        // The block is not large enough to be split, so allocate the entire block.
        if (previousBlock != NULL) {
            previousBlock->next = currentBlock->next;
        } else {
            freeListHead = currentBlock->next;
        }
    }

    // Set up the header for the allocated block.
    AllocatedBlockHeader* allocatedHeader = (AllocatedBlockHeader*)currentBlock;
    allocatedHeader->blockSize = currentBlock->blockSize;

    // Update statistics.
    totalAllocatedMemory += allocatedHeader->blockSize;
    totalFreeMemory -= allocatedHeader->blockSize;
    allocationCount++;

    // Return a pointer to the user data area (after the header).
    return (void*)((unsigned char*)allocatedHeader + sizeof(AllocatedBlockHeader));
}

/**
 * @brief Frees a previously allocated block of memory.
 *
 * @param ptr A pointer to the memory block to be freed.
 */
void customFree(void* ptr) {
    if (ptr == NULL) {
        return;
    }

    // Get the header of the allocated block.
    AllocatedBlockHeader* allocatedHeader = (AllocatedBlockHeader*)((unsigned char*)ptr - sizeof(AllocatedBlockHeader));

    // Update statistics.
    totalAllocatedMemory -= allocatedHeader->blockSize;
    totalFreeMemory += allocatedHeader->blockSize;
    freeCount++;

    // Convert the allocated block back to a free block.
    FreeBlockHeader* newFreeBlock = (FreeBlockHeader*)allocatedHeader;
    newFreeBlock->blockSize = allocatedHeader->blockSize;

    // Insert the new free block into the free list, maintaining sorted order by address.
    FreeBlockHeader* currentBlock = freeListHead;
    FreeBlockHeader* previousBlock = NULL;

    while (currentBlock != NULL && currentBlock < newFreeBlock) {
        previousBlock = currentBlock;
        currentBlock = currentBlock->next;
    }

    if (previousBlock == NULL) {
        // Insert at the head of the free list.
        newFreeBlock->next = freeListHead;
        freeListHead = newFreeBlock;
    } else {
        newFreeBlock->next = previousBlock->next;
        previousBlock->next = newFreeBlock;
    }

    // Coalesce (merge) with the next block if it is free and adjacent.
    if (newFreeBlock->next != NULL &&
        (unsigned char*)newFreeBlock + newFreeBlock->blockSize == (unsigned char*)newFreeBlock->next) {
        newFreeBlock->blockSize += newFreeBlock->next->blockSize;
        newFreeBlock->next = newFreeBlock->next->next;
    }

    // Coalesce with the previous block if it is free and adjacent.
    if (previousBlock != NULL &&
        (unsigned char*)previousBlock + previousBlock->blockSize == (unsigned char*)newFreeBlock) {
        previousBlock->blockSize += newFreeBlock->blockSize;
        previousBlock->next = newFreeBlock->next;
    }
}

/**
 * @brief Reallocates a block of memory.
 *
 * @param ptr A pointer to the previously allocated memory.
 * @param newSize The new size for the memory block.
 * @return A pointer to the reallocated memory, or NULL if the reallocation fails.
 */
void* customRealloc(void* ptr, size_t newSize) {
    if (ptr == NULL) {
        // If the original pointer is NULL, it's equivalent to malloc.
        return customMalloc(newSize);
    }

    if (newSize == 0) {
        // If the new size is 0, it's equivalent to free.
        customFree(ptr);
        return NULL;
    }

    AllocatedBlockHeader* oldHeader = (AllocatedBlockHeader*)((unsigned char*)ptr - sizeof(AllocatedBlockHeader));
    size_t oldSize = oldHeader->blockSize - sizeof(AllocatedBlockHeader);

    if (newSize <= oldSize) {
        // The new size is smaller or equal, so we can reuse the existing block.
        return ptr;
    }

    // The new size is larger, so we need to allocate a new block and copy the data.
    void* newPtr = customMalloc(newSize);
    if (newPtr == NULL) {
        return NULL; // Failed to allocate a new block.
    }

    // Copy the contents from the old block to the new one.
    memcpy(newPtr, ptr, oldSize);

    // Free the old block.
    customFree(ptr);

    return newPtr;
}


/**
 * @brief Prints statistics about the memory allocator's state.
 */
void printMemoryStats() {
    printf("\n--- Memory Allocator Statistics ---\n");
    printf("Total Memory Pool Size: %zu bytes\n", (size_t)MEMORY_POOL_SIZE);
    printf("Total Allocated Memory: %zu bytes\n", totalAllocatedMemory);
    printf("Total Free Memory:      %zu bytes\n", totalFreeMemory);
    printf("Total Allocations:      %zu\n", allocationCount);
    printf("Total Frees:            %zu\n", freeCount);

    printf("\n--- Free List ---\n");
    FreeBlockHeader* current = freeListHead;
    int i = 0;
    while (current != NULL) {
        printf("Block %d: Address = %p, Size = %zu bytes\n", i++, (void*)current, current->blockSize);
        current = current->next;
    }
    printf("-----------------------------------\n\n");
}

int main() {
    // Initialize the allocator before any allocations.
    initializeAllocator();

    printf("Initial state of the allocator:\n");
    printMemoryStats();

    // Perform some allocations.
    printf("Allocating 128 bytes for ptr1...\n");
    void* ptr1 = customMalloc(128);
    printMemoryStats();

    printf("Allocating 256 bytes for ptr2...\n");
    void* ptr2 = customMalloc(256);
    printMemoryStats();

    printf("Allocating 512 bytes for ptr3...\n");
    void* ptr3 = customMalloc(512);
    printMemoryStats();

    // Free one of the blocks.
    printf("Freeing ptr2 (256 bytes)...\n");
    customFree(ptr2);
    printMemoryStats();

    // Allocate another block to see if the freed space is reused.
    printf("Allocating 64 bytes for ptr4...\n");
    void* ptr4 = customMalloc(64);
    printMemoryStats();

    // Free all remaining blocks.
    printf("Freeing ptr1 (128 bytes)...\n");
    customFree(ptr1);
    printMemoryStats();

    printf("Freeing ptr3 (512 bytes)...\n");
    customFree(ptr3);
    printMemoryStats();

    printf("Freeing ptr4 (64 bytes)...\n");
    customFree(ptr4);
    printMemoryStats();

    // Test reallocation.
    printf("Allocating 100 bytes for realloc_ptr...\n");
    void* realloc_ptr = customMalloc(100);
    strcpy((char*)realloc_ptr, "This is a test string.");
    printf("Original string: %s\n", (char*)realloc_ptr);
    printMemoryStats();

    printf("Reallocating realloc_ptr to 200 bytes...\n");
    realloc_ptr = customRealloc(realloc_ptr, 200);
    printf("String after realloc: %s\n", (char*)realloc_ptr);
    printMemoryStats();

    printf("Freeing realloc_ptr...\n");
    customFree(realloc_ptr);
    printMemoryStats();

    return 0;
}
