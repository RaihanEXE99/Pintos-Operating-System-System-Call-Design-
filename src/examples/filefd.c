#include <syscall.h>
#include <stdio.h>
int main(void) {
  int f = 0;
  unsigned pos = tell(f);
  printf("Position of file pointer for fd %d: %u\n", f, pos);
  return 0;
}