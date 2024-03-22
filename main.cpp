#include <sys/mman.h>
#include <signal.h>
#include <sys/ucontext.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <assert.h>
#include <string.h>
#include <queue>
#include <deque>
#include <iostream>
#include <tuple>
#include <map>

const auto PAGE_SIZE = sysconf(_SC_PAGESIZE); // more (POSIX) portable version of getpagesize()
constexpr size_t HEAP_POOL_SIZE = 2; // size of the memory pool to allocate out of, in pages
constexpr int TODO_NUM = 48109; // placeholder for where an integer is expected

/* forward declare everything
 *
 * see definitions below for explanations
 */
void *simple_allocator();
void simple_free(void *);
std::tuple<void *, std::queue<void *>, std::map<void *, bool>> init_heap();
void fault_handler(int, siginfo_t *, void *);
template<typename T>
void print_queue(std::queue<T>, const std::string &);

// shared state between the allocation functions
auto [heap_pool_start, free_pages, page_info] = init_heap();

// this is a macro so we calculate it every time
#define heap_pool_max_addr static_cast<void *>(static_cast<char *>(heap_pool_start) + (HEAP_POOL_SIZE * PAGE_SIZE))

int main(){
    std::cout << "page size we're using: " << PAGE_SIZE << " bytes\n";
    // handle segfaults with sigaction
    struct sigaction signal_action;
    signal_action.sa_sigaction = &fault_handler;
    //signal_action.sa_mask = 0; // don't mask any other signals while we handle this
    signal_action.sa_flags = SA_SIGINFO // use .sa_sigaction instead of .sa_handler
        | SA_NODEFER; // don't even mask this signal while we handle it
    if(sigaction(SIGSEGV, &signal_action, NULL)){ // install our segfault handler
        perror("sigaction");
        exit(EXIT_FAILURE);
    }
    void *p0 = simple_allocator(); // allocate one page
    void *p1 = simple_allocator(); // allocate another page
    std::cout << "The next line should write fault\n";
    strcpy(static_cast<char *>(p0), "This line should write fault, since the page is no longer zeroed");
    std::cout << "string p0 is \"" << static_cast<char *>(p0) << "\"\n";
    simple_free(p0); // give back the first page
    void *p2 = simple_allocator(); // allocate the same address as p0, since HEAP_POOL_SIZE = 2
    assert(p0 == p2);
    std::cout << "The next line should read fault\n";
    auto c = static_cast<char *>(p2)[0];
    assert(c == 0);
    std::cout << "The next line should not read fault\n";
    auto d = static_cast<char *>(p2)[1];
    assert(d == 0);
    std::cout << "The next line should write fault\n";
    strcpy(static_cast<char *>(p2), "A different string than before");
    std::cout << "string p2 is \"" << static_cast<char *>(p2) << "\"\n";
}

/*
 * This simple dynamic memory allocator either returns a pointer to a page
 * size of zeroed out memory, or returns NULL on failure.
 */
void *simple_allocator(){
    print_queue(free_pages, "free_pages (before popping)");
    if(free_pages.empty()){
        std::cout << __PRETTY_FUNCTION__ << ": no more free pages\n";
        return nullptr;
    }
    else{
        auto p = free_pages.front();
        free_pages.pop();
        if(page_info.at(p)){ // page is zeroed
            if(mprotect(p, PAGE_SIZE, /* TODO: set the protection as needed */ TODO_NUM)){
                perror("mprotect");
                assert(false);
            }
        }
        else{ // page is not zeroed
            if(mprotect(p, PAGE_SIZE, /* TODO: set the protection as needed */ TODO_NUM)){
                perror("mprotect");
                assert(false);
            }
        }
        std::cout << __PRETTY_FUNCTION__ << ": returning " << p << "\n";
        return p;
    }
}

/*
 * This is a hack to initialize the heap
 *
 * THIS SHOULD NOT BE USED ANYWHERE ELSE
 */
std::tuple<void *, std::queue<void *>, std::map<void *, bool>> init_heap(){
    // use mmap to initialize heap_pool_start with zeroed swap-backed pages
    // ask the OS for HEAP_POOL_SIZE pages of swap-backed memory, for our heap
    void *heap_pool_start = mmap(NULL, HEAP_POOL_SIZE * PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    // track whether a given heap page is free, and whether it's zeroed out
    std::queue<void *> free_pages;
    std::map<void *, bool> page_info;
    for(size_t i = 0; i < HEAP_POOL_SIZE; i++){
        void *p = static_cast<char *>(heap_pool_start) + (i * PAGE_SIZE);
        free_pages.push(p);
        auto [_, happened] = page_info.try_emplace(p, true /* mmap MAP_ANONYMOUS allocates zeroed out memory*/);
        assert(happened);
    }
    std::cout << /* full type is too long */ __FUNCTION__ << ": heap memory pool range is [" << heap_pool_start << ", " << heap_pool_max_addr << ")\n";
    return std::make_tuple(heap_pool_start, free_pages, page_info);
}

void simple_free(void *p){
    /* We don't do any error checking, but you'd want to check whether p is
     * - within the memory pool range
     * - page aligned
     * - not already free
     */
    std::cout << __PRETTY_FUNCTION__ << ": freeing " << p << "\n";
    free_pages.push(p);
    print_queue(free_pages, "free_pages (after pushing)");
}

void fault_handler(int signal_number, siginfo_t *signal_info, void *ucp){
    // faulting memory address
    void *addr = signal_info->si_addr;
    auto execution_context = static_cast<ucontext_t *>(ucp);
#if defined(__linux__) && defined(__x86_64__)
    auto error_code = execution_context->uc_mcontext.gregs[REG_ERR]; // see bottom of file
    /* 0 = read, 1 = write fault */
    // see the kernel header /arch/x86/include/asm/trap_pf.h
    bool write = error_code & (1<<1);
#else
#error "This will only work on x86_64 linux. The p3 infrastructure supports more systems, and this could be extended, but it has to be done on a case by case basis since we rely on architecture specific details of ucontext_t"
#endif
    std::cout << __PRETTY_FUNCTION__ << ": Got a " << ((write)? "write" : "read") << " fault at " << addr << "\n";
    void *addr_page = /* TODO: calculate the starting address of the page `addr` in on */ nullptr;
    if(write){ // write fault
        /* TODO: Handle a write fault
         *
         * Besides calling `mprotect` and `memset` as needed, don't forget to
         * update `page_info.at(addr_page)` to track whether addr_page is
         * zeroed out or not
         */
    }
    else{ // read fault
        /* TODO: Handle a read fault
         */
    }
    std::cout << __PRETTY_FUNCTION__ << ": returning, with page_info.at(addr_page) = " << page_info.at(addr_page) << "\n";
    return;
}

template<typename T>
void print_queue(std::queue<T> q, const std::string &msg){
    // debug printing
    std::cout << msg << " = { ";
    while(!q.empty()){
        std::cout << q.front() << ", ";
        q.pop();
    }
    std::cout << "}\n";
}

/*
 * NOTE: How do we detect if the fault was from a read or write?
 *
 * This exact question was answered at https://stackoverflow.com/q/17671869
 * but note that while the general structure still seems to hold, some of
 * the code has moved around in the kernel
 * (This is essentially what the infra does)
 * 
 * see /usr/include/x86_64-linux-gnu/sys/ucontext.h
 * and /usr/include/asm-generic/ucontext.h
 * aka the kernel header /include/uapi/asm-generic/ucontext.h
 */
