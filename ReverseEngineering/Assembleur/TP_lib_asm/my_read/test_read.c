#include <assert.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

ssize_t my_read(int fd, void *buf, size_t nbytes);

int main() {
  FILE *ptr = fopen("../", "r");
  int fd = fileno(ptr);

  char buf[32];
  int n = read(fd, buf, 5);

  printf("%d", n);
  printf("%s", buf);

  n = my_read(fd, buf, 5);

  printf("%d", n);
  printf("%s", buf);

  fclose(ptr);
  return 0;
}