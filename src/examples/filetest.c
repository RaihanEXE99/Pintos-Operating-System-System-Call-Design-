#include <syscall.h>
#include <stdio.h>

int main(void) {
  int fd = 0;  // Assume file descriptor 0 represents stdin
  unsigned position = tell(fd);

  printf("Current position of file pointer for fd %d: %u\n", fd, position);

  return 0;
}
