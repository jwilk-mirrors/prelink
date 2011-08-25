#include "cxx3.h"
extern "C" void abort (void);

void
check (A *x, B *y)
{
  C d;
  if (x->b () != 2)
    abort ();
  if (y->B::a () != 3)
    abort ();
  if (d.a () != 4)
    abort ();
  if (d.C::b () != 5)
    abort ();
}

int
main ()
{
  A x;
  if (x.a () != 1)
    abort ();
  do_check (check, &x);
  return 0;
}
