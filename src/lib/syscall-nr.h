#ifndef __LIB_SYSCALL_NR_H
#define __LIB_SYSCALL_NR_H

/* System call numbers. */
enum 
  {
    SYS_HALT,                   
    SYS_EXIT,                   
    SYS_EXEC,                   
    SYS_WAIT,                   
    SYS_CREATE,                 
    SYS_REMOVE,                 
    SYS_OPEN,                   
    SYS_FILESIZE,              
    SYS_READ,                  
    SYS_WRITE,                 
    SYS_SEEK,                   
    SYS_TELL,                  
    SYS_CLOSE,                  
  };

#endif /* lib/syscall-nr.h */
