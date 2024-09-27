#include <assert.h>
#include <ctype.h>
#include <stdio.h>

int my_isalpha(int c);

int main() {
  printf("%d\n", my_isalpha('a'));
  printf("%d\n", isalpha('a'));

  printf("%d\n", my_isalpha('1'));
  printf("%d\n", isalpha('1'));
  return 0;
}