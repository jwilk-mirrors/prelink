#include "ifunc.h"

static int bint11 (void) { return 1; }
static int bint12 (void) { return 2; }

IFUNC_LOCAL (bint1, bint11, bint12);

static int lib2t21 (void) { return 1; }
static int lib2t22 (void) { return 2; }

IFUNC_GLOBAL (lib2t2, lib2t21, lib2t22);

extern int lib1t2 (void);
extern int lib1test (void);
extern int lib2test (void);

extern void abort (void);

int
main (void)
{
  lib1test ();
  lib2test ();
  if (bint1 () != PICKNO)
    abort ();
  if (lib1t2 () != PICKNO)
    abort ();
  return 0;
}
