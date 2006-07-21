#include "reloc1.h"
#include <stdlib.h>

extern char testzero[16384];

int main()
{
  int i;
  if (foo.a != 1 || foo.b != &foo || foo.c != &bar || bar != 26)
    abort ();
  if (f1 () != 11 || f2 () != 12)
    abort ();
  for (i = 0; i < 16384; ++i)
    if (testzero[i])
      abort ();
  exit (0);
}

asm (".section nonalloced,\"aw\",@nobits; testzero: .skip 16384");
