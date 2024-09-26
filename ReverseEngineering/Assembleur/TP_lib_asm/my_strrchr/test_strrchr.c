#include <assert.h>
#include <ctype.h>
#include <stdio.h>
#include <string.h>

// The strrchr() function returns a pointer to the last occurrence of the
// character  c in the string s.
//

char *my_strrchr(const char *s, int c);

int main() {
  char *string = "abcdeabcde";
  char *ptr = my_strrchr(string, '\0');
  printf("%p\n", string);
  printf("%p\n", ptr);

  ptr = strrchr(string, '\0');
  printf("%p\n", string);
  printf("%p\n", ptr);
  return 0;
}