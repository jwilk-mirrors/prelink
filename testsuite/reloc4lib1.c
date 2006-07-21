#include <stdio.h>

int main (void)
{
  int i;

  for (i = 0; i < 65536; ++i)
    printf ("int foo%04x (void) { return %d; }\n", i, (i & 31) == 0 ? 0 : i);
}
