#include <stdio.h>

int main (void)
{
  int i;

  for (i = 0; i < 65536; i += 32)
    printf ("int foo%04x (void) { return %d; }\n", i, i);
}
