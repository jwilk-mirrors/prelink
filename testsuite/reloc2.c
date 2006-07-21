#include <stdlib.h>

extern int f2 (int add);
extern void * f3 (void);

int main()
{
  if (f2 (1) != 27 || f2 (0) != 1)
    abort ();
  if (f3 () != (void *) f3)
    abort ();
  exit (0);
}
