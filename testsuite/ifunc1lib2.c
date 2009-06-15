#include "ifunc.h"

static int lib2t11 (void) { return 1; }
static int lib2t12 (void) { return 2; }

IFUNC_LOCAL (lib2t1, lib2t11, lib2t12);

static int lib2t21 (void) { return 3; }
static int lib2t22 (void) { return 4; }

IFUNC_GLOBAL (lib2t2, lib2t21, lib2t22);

static int lib2t31 (void) { return 1; }
static int lib2t32 (void) { return 2; }

IFUNC_GLOBAL (lib2t3, lib2t31, lib2t32);

static int lib1t31 (void) { return 1; }
static int lib1t32 (void) { return 2; }

IFUNC_GLOBAL (lib1t3, lib1t31, lib1t32);

int (*lib2p1) (void) = lib2t2;

extern void abort (void);

int
lib2test (void)
{
  if (lib2t1 () != PICKNO)
    abort ();
  if (lib2t2 () != PICKNO)
    abort ();
  if (lib2t3 () != PICKNO)
    abort ();
  if (lib2p1 () != PICKNO)
    abort ();
  return 0;
}
