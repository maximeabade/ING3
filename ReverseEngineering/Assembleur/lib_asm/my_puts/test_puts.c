#include <assert.h>
#include <ctype.h>
#include <stdio.h>

int my_puts(const char *s);

int main() {
  my_puts("hello world");
  printf("%d", puts("hello world"));
  printf("%d", my_puts("hello world"));
  // printf("%d", my_puts(""));
  printf("\n%d\n", EOF);
  return 0;
}