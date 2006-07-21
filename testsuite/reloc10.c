#include <stdlib.h>

extern int bar, baz, *barp, *bazp, dummy;
extern int f1 (void), f2 (void), f3 (void), f4 (void);
/* Try to use COPY reloc for bar and get away without COPY
   reloc for baz.  Similarly for barp and bazp.  */
int *bazp2 = &baz;
int **bazp3 = &bazp;

int main (void)
{
  if (f1 () != 11 || f2 () != 12 || bar != 36 || *bazp2 != 38)
    abort ();
  if (f3 () != 14 || f4 () != 16 || *barp != 36 || **bazp3 != 38)
    abort ();
  if (dummy != 24)
    abort ();
  exit (0);
}
