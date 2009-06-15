#include "ifunc.h"

static int lib1t11 (void) { return 11; }
static int lib1t12 (void) { return 12; }

IFUNC_LOCAL (lib1t1, lib1t11, lib1t12);

static int lib1t21 (void) { return 1; }
static int lib1t22 (void) { return 2; }

IFUNC_GLOBAL (lib1t2, lib1t21, lib1t22);

static int lib1t31 (void) { return 3; }
static int lib1t32 (void) { return 4; }

IFUNC_GLOBAL (lib1t3, lib1t31, lib1t32);

extern void abort (void);

int (*lib1p1) (void) = lib1t1;

int
lib1test (void)
{
  if (lib1t1 () != PICKNO + 10)
    abort ();
  if (lib1t3 () != PICKNO)
    abort ();
  if (lib1p1 () != PICKNO + 10)
    abort ();
  return 0;
}
