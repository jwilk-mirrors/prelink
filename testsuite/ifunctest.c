#include "ifunc.h"

static int foo1 (void) { return 1; }
static int foo2 (void) { return 2; }

IFUNC_LOCAL (foo, foo1, foo2);

extern void abort (void);

int
main (void)
{
  if (foo () != PICKNO)
    abort ();
  return 0;
}
