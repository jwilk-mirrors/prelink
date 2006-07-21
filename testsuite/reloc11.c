#include <stdlib.h>

extern int dummy;
extern int var, var2, varp1 (), var2m1 (), bar ();
int *pvar = &var, *pvar2 = &var2;

int main (void)
{
  if (dummy != 24)
    abort ();
  if (*pvar != 32 || *pvar2 != 16)
    abort ();
  if (varp1 () != 33 || var2m1 () != 6 || bar () != 40)
    abort ();
  exit (0);
}
