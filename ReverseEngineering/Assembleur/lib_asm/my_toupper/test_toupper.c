#include <assert.h>
#include <ctype.h>
#include <stdio.h>

int my_toupper(int c);

int main() {
  // assert(my_toupper('a') == toupper('a'));
  printf("%c\n", my_toupper('a'));
  printf("%c\n", toupper('a'));

  printf("%c\n", my_toupper(' '));
  printf("%c\n", my_toupper('c'));
  return 0;
}