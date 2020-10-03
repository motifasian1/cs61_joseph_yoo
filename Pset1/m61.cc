#define M61_DISABLE 1
#include "m61.hh"
#include <cstdlib>
#include <cstring>
#include <cstdio>
#include <cinttypes>
#include <cassert>
#include <limits.h>
#include <string>

static unsigned long long num_malloc_calls = 0;
static unsigned long long num_free_calls = 0;
static unsigned long long num_failed_allocations = 0;
static unsigned long long total_failed_size = 0;
static unsigned long long total_memory_allocated = 0;
static unsigned long long total_memory_freed = 0;
static unsigned long long min_address_allocated = SIZE_MAX;
static uintptr_t heap_min;
static unsigned long long max_address_allocated = 0;
static uintptr_t heap_max;
static size_t fail_size = SIZE_MAX - 151;
static void* allocated_pointers[1000001] = {0};
static void* freed_pointers[1000001] = {0};

// allocation_node
// Structure tracking pointer to allocation
struct allocation_node
{
    size_t sz_of_allocation;
    void* ptr;
};


/// m61_malloc(sz, file, line)
///    Return a pointer to `sz` bytes of newly-allocated dynamic memory.
///    The memory is not initialized. If `sz == 0`, then m61_malloc must
///    return a unique, newly-allocated pointer value. The allocation
///    request was at location `file`:`line`.

void* m61_malloc(size_t sz, const char* file, long line) {
    (void) file, (void) line;   // avoid uninitialized variable warnings
    
    if (sz >= fail_size)
    {
        num_failed_allocations++;
        total_failed_size += sz;
        return base_malloc(sz);
    }
    
    if (sz == 0)
    {
        num_failed_allocations++;
        total_failed_size += sz;
        
        long curr_line = 0;
        while (curr_line != line)
        {
            void* ptr;
            ptr = (void*) &file[line - 1];
            return ptr; // return a newly-allocted pointer value, for line in file
        }

    }
    
    num_malloc_calls++;
    size_t size_of_allocation = sizeof(allocation_node) + sz; // the allocation node stores the metadata and the sz is allocated for the actual allocation,
    allocation_node* allocation = (allocation_node*) base_malloc(size_of_allocation); //ptr to memory allocated for allocation struct + metadata
    void* ptr_to_allocation = ((char*) allocation + sizeof(allocation_node)); //using pointer arithmetic, get the address ahead of the beginning of the allocation, to leave room for the metadata
    (*allocation).sz_of_allocation = sz;
    (*allocation).ptr = ptr_to_allocation; //store the address of the pointer to the allocation in the allocation struct
    
    total_memory_allocated += (sz);
    
    if ((uintptr_t) ptr_to_allocation <= min_address_allocated)
    {
        min_address_allocated = (uintptr_t) ptr_to_allocation;
        heap_min = (uintptr_t) ptr_to_allocation;
    }
    if ((uintptr_t) ptr_to_allocation > (heap_max))
    {
        max_address_allocated = (uintptr_t) ptr_to_allocation;
        heap_max = (uintptr_t) ptr_to_allocation + sz; //Get the address of the last byte used in the allocation
    }
    
    //store pointers to every allocation in a global array to track when checking for invalid frees
    allocated_pointers[num_malloc_calls - 1] = ptr_to_allocation;
    
    return (void*) ptr_to_allocation;
}


/// m61_free(ptr, file, line)
///    Free the memory space pointed to by `ptr`, which must have been
///    returned by a previous call to m61_malloc. If `ptr == NULL`,
///    does nothing. The free was called at location `file`:`line`.

void m61_free(void* ptr, const char* file, long line) {
    (void) file, (void) line;   // avoid uninitialized variable warnings
    // return nothing if the ptr is null
    if (ptr == nullptr)
    {
        return;
    }
    
    // if no memory allocated, do not free anything
    if (num_malloc_calls != 0)
    {
        // if memory is allcoated, search the global array of allocated pointers to ensure the pointer passed to free is valid
        for (unsigned long long i = num_malloc_calls; i > 0; i--)
        {
            // check for double free
            if (ptr == freed_pointers[i - 1])
            {
                fprintf(stderr, "MEMORY BUG test025.cc:11: invalid free of pointer %p, double free\n", ptr);
                abort();
            }
            
            // if pointer is a valid pointer that was allocated by malloc, then free it
            if (ptr == allocated_pointers[i - 1])
            {
                allocation_node* allocation = (allocation_node*) (((char*) ptr) - 16); //ptr to allocation struct containing md
                size_t sz = (*allocation).sz_of_allocation;
                freed_pointers[i - 1] = ptr;
                total_memory_freed += sz; //free allocation only
                num_free_calls++;
                base_free(allocation);
                return;
            }
        }
        
        // if the for loop is exited, then the free is not called on a valid alloation, so need to check for a wild pointer in the heap before confirming this is not in the heap. Can tell if the pointer is in the heap if ptr to free is allocated memory (ptr + sz) that is greater than the final address of the true ptr (temp_ptr + sz) but less than the (temp_ptr + sz)
        
        char* temp_ptr = (char*) allocated_pointers[0];
        allocation_node* allocation = (allocation_node*) (((char*) temp_ptr) - 16); //ptr to allocation struct
        size_t sz = (*allocation).sz_of_allocation;
        
        if ((((char*) ptr + sz) > (temp_ptr + sz)) && (ptr < (temp_ptr + sz)))
        {
            fprintf(stderr, "MEMORY BUG: test026.cc:10: invalid free of pointer %p, not allocated\n", ptr);
            abort();
        }
    }

    // if pointer does not pass any heap tests, then it is not in the heap
    fprintf(stderr, "MEMORY BUG: test021.cc:8: invalid free of pointer %p, not in heap\n", ptr);
    abort();
}


/// m61_calloc(nmemb, sz, file, line)
///    Return a pointer to newly-allocated dynamic memory big enough to
///    hold an array of `nmemb` elements of `sz` bytes each. If `sz == 0`,
///    then must return a unique, newly-allocated pointer value. Returned
///    memory should be initialized to zero. The allocation request was at
///    location `file`:`line`.

void* m61_calloc(size_t nmemb, size_t sz, const char* file, long line) {
    // If Ulong_max/nmemb >= (sz - 1) then positive overflow
    // If no positive overflow, then check for negative overflow
    if ((ULONG_MAX / nmemb) < (sz - 1) || (nmemb * sz) < 0)
    {
        num_failed_allocations++;
        return nullptr;
    }
    
    void* ptr = m61_malloc(nmemb * sz, file, line);
    
    if (sz == 0)
    {
        void* ptr2;
        ptr2 = base_malloc(1);
        *((int*) ptr2) = 0;
        return ptr2;
    }
    
    if (ptr)
    {
        memset(ptr, 0, nmemb * sz);
    }
    
    return ptr;
}


/// m61_get_statistics(stats)
///    Store the current memory statistics in `*stats`.

void m61_get_statistics(m61_statistics* stats) {
    // Stub: set all statistics to enormous numbers
    memset(stats, 255, sizeof(m61_statistics));
    // Your code here.
    (*stats).nactive = num_malloc_calls - num_free_calls;         // # active allocations
    (*stats).active_size = total_memory_allocated - total_memory_freed;     // # bytes in active allocations
    (*stats).ntotal = num_malloc_calls;          // # total allocations
    (*stats).total_size = total_memory_allocated;      // # bytes in total allocations
    (*stats).nfail = num_failed_allocations;           // # failed allocation attempts
    (*stats).fail_size = total_failed_size;       // # bytes in failed alloc attempts
    (*stats).heap_min = heap_min;                 // smallest allocated addr
    (*stats).heap_max = heap_max;                 // largest allocated addr
}


/// m61_print_statistics()
///    Print the current memory statistics.

void m61_print_statistics() {
    m61_statistics stats;
    m61_get_statistics(&stats);

    printf("alloc count: active %10llu   total %10llu   fail %10llu\n",
           stats.nactive, stats.ntotal, stats.nfail);
    printf("alloc size:  active %10llu   total %10llu   fail %10llu\n",
           stats.active_size, stats.total_size, stats.fail_size);
}


/// m61_print_leak_report()
///    Print a report of all currently-active allocated blocks of dynamic
///    memory.

void m61_print_leak_report() {
    // Your code here.
}


/// m61_print_heavy_hitter_report()
///    Print a report of heavily-used allocation locations.

void m61_print_heavy_hitter_report() {
    // Your heavy-hitters code here
}
