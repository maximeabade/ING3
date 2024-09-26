#include <assert.h>
#include <ctype.h>
#include <stdio.h>
#include <string.h>

char *my_strcat(char *restrict dst, const char *restrict src);

int main() {
  /*char dst[128] = {'x', 'e', 'x', 'e', 'x', 'e', '\0'};
  char *ptr = my_strcat(dst, "abc");
  printf("%p\n", ptr);
  printf("%s\n", ptr);

  ptr = strcat(dst, "zzz");
  printf("%p\n", ptr);
  printf("%s\n", ptr);*/

  char buf1[300000];
  char buf2[300000];
  char suffix[0x1ffff + 1];
  char *ret2;

  memset(buf1, '\0', 300000);
  memset(buf2, '\0', 300000);
  memset(suffix + 1, 0xfd, 0x1ffff - 1);
  my_strcat(buf1, "hello world");
  printf("%s\n", buf1);
  /*
  ptr = my_strcat(buf1, buf2);
  printf("%p\n", ptr);
  printf("%s\n", ptr);*/

  return 0;
}