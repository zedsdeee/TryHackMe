Introduction

The vulnerability “Dirty Cow” came from the “dirty” bit and copy-on-write(COW). Dirty Cow is a vulnerability that occurs in the kernel’s memory subsystem so as to race condition. A race condition vulnerability was found in the way the Linux kernel’s memory subsystem handled the copy-on-write breakage of private read-only memory mappings. It deliberately creates an error during copy-on-write by repeating the processes and it tricks the kernel into actually writing to the underlying file.

Basically it is possible to privilege escalation by writing in to /etc/passwd or sudo binary files.
Background

    Kernel subsystem: The Kernel subsystem is responsible for fairly distributing the CPU time among all the processes running on the system simultaneously.
    Race condition: Race conditions occur when two computer program processes, or threads, attempt to access the same resource at the same time and cause problems in the system. Race conditions are considered a common issue for multithreaded applications.
    Overhead: CPU overhead measures the amount of work a computer’s central processing unit can perform and the percentage of that capacity that’s used by individual computing tasks.
    Copy-on-write: Copy On Write (CoW) is a method in which multiple processes continue to share the same physical memory until a write actually occurs
    Dirty bit: A dirty bit is a binary value used by computer systems to track whether a specific unit of data, such as a cache line or a memory page, has been modified.

Analysis and Exploitation

https://github.com/dirtycow/dirtycow.github.io/blob/master/dirtyc0w.c

    Step1: open the root file in read only mode.

f=open(argv[1],O_RDONLY);
fstat(f,&st);
name=argv[1];

    Step2: mmap maps a file into memory. copy-on-write

Normally, Copy-on-write(COW) occurs when you try to write something to mapped read-only memory. Copy-on-write means, if you were to write to the memory segment, you write to the copy of the memory. Updates to the mapping are not visible to other processes mapping the same file, and are not carried through to the underlying file. It is unspecified whether changes made to the file after the mmap() call are visible in the mapped region.

map=mmap(NULL,st.st_size,PROT_READ,MAP_PRIVATE,f,0); 
printf("mmap %zx\n\n",(uintptr_t) map);

You have to use MAP_PRIVATE for copy-on-write mapping. PROT_READ shows the mapped file is only readable. Create a private copy-on-write mapping.

    Step3: Start two threads to create copy-on-write race conditions.

pthread_create(&pth1,NULL,madviseThread,argv[1]);
pthread_create(&pth2,NULL,procselfmemThread,argv[2]);

Both threads will run in parallel. DirtyCow is a race condition vulnerability. It means certain events have to occur in a specific order, that are unlikely to happen under normal conditions.

    Step 3.1: Madvise Thread

First thread uses the syscall madvise(). The madvise system call is used to give advice or directions to the kernel about the address range

void *madviseThread(void *arg)
{
 char *str;
 str=(char*)arg;
 int i,c=0;
 for(i=0;i<100000000;i++)
 {
/*
You have to race madvise(MADV_DONTNEED) :: https://access.redhat.com/security/vulnerabilities/2706661
> This is achieved by racing the madvise(MADV_DONTNEED) system call
> while having the page of the executable mmapped in memory.
*/
 c+=madvise(map,100,MADV_DONTNEED);
 }
 printf("madvise %d\n\n",c);
}

First 100 byte is MADV_DONTNEED which means that it does not expect access in the near future. Subsequent accesses of pages in the range will succeed, but will result in either repopulating the memory contents from the up-to-date contents of the underlying mapped file.

    Step 3.2: write to proc/self/mem thread (R/O to R/W by proc/self/mem)

void *procselfmemThread(void *arg)
{
 char *str;
 str=(char*)arg;
/*
You have to write to /proc/self/mem :: https://bugzilla.redhat.com/show_bug.cgi?id=1384344#c16
> The in the wild exploit we are aware of doesn't work on Red Hat
> Enterprise Linux 5 and 6 out of the box because on one side of
> the race it writes to /proc/self/mem, but /proc/self/mem is not
> writable on Red Hat Enterprise Linux 5 and 6.
*/
 int f=open("/proc/self/mem",O_RDWR);
 int i,c=0;
 for(i=0;i<100000000;i++) {
/*
You have to reset the file pointer to the memory position.
*/
 lseek(f,(uintptr_t) map,SEEK_SET);
 c+=write(f,str,strlen(str));
 }
 printf("procselfmem %d\n\n", c);
}

First, mmap R/O file to memory by MAP_PRIVATE -> R/O map created. And next, open /proc/self/mem file by open() as if it is a file -> R/W file opened

If you access the virtual address offset from R/W file (proc/self/mem), you can request write operation to R/O disk map. Of course, when R/W is requested like that, Copy on Write occurs and writing is done to the private copy rather than to the actual disk, so there is no direct security threat ‘as of yet’.

/proc : the information about the processes

/proc/self : the current process

/proc/self/mem : the memory (r/w permission)

Second, thread proc/self/mem thread opens the file /proc/self/mem and writes to this file in a loop. This is a thread that repeatedly sends write requests for the R/O map to the kernel through /proc/self/mem.

At the point when Copy on Write occurs, the kernel determines that memory write permission is secured and seeks the page. At this time, the private copy page is tossed by madvise(DONT_NEED). If you write to the copied mapped memory, the memory page gets flagged as dirty. But you do not care that the dirty page has not been written.

So this madvise call causes the throwing away of this memory. This means it is not any of the memory caches anymore. The page is searched again, it will create a edgecase that usually does not occur since it determined that write permission has been secured earlier, tricking the kernel into actually writing to the “actual” map page and write permission is not checked.

If a race condition occurs in this order, you can write whatever you want to the read-only file because every time when we try to write, the copy of the memory might have been tossed so we have to reload a new copy from memory so we can write to it.

The patch added a function that checks if the copy-on-write is complete yet, and only then allows writing to it.

https://www.youtube.com/watch?v=kEsshExn7aE&ab_channel=LiveOverflow
