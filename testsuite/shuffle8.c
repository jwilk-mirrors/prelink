#include "reloc1.h"
#include <stdlib.h>

static struct A local = { 77, &local, &bar + 4 };
int vbss[16384] __attribute__((aligned (4096)));
int vdata __attribute__((aligned (4096))) = 5;

asm (".text; .balign 4096; vtext:; .previous");

int main()
{
  if (foo.a != 1 || foo.b != &foo || foo.c != &bar || bar != 26)
    abort ();
  if (f1 () != 11 || f2 () != 12)
    abort ();
  local.c -= 4;
  if (local.a != 77 || local.b != &local || local.c != &bar)
    abort ();
  exit (vbss[31] + vdata - 5);
}
