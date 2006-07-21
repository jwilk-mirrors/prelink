#include "reloc1.h"
#include <stdlib.h>

static struct A local = { 77, &local, &bar + 4 };
extern int baz;
static char *bazp0 = (char *) &baz;
static char *bazp1 = ((char *) &baz) + 1;

int main()
{
  if (foo.a != 1 || foo.b != &foo || foo.c != &bar || bar != 26)
    abort ();
  if (f1 () != 11 || f2 () != 12)
    abort ();
  local.c -= 4;
  if (local.a != 77 || local.b != &local || local.c != &bar)
    abort ();
  if (bazp1 - bazp0 != 1)
    abort ();
  exit (0);
}
