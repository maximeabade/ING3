#include <assert.h>
#include <stdio.h>
#include <string.h>

extern int my_strcmp(char *s1, char *s2);

int main() {
  printf("%d", my_strcmp("a", "a"));
  printf("%d", my_strcmp("abbb", "abbb"));
  printf("%d", my_strcmp("a", "b"));
  printf("%d", my_strcmp("b", "a"));
  return 0;
}