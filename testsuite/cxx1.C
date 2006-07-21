#include "cxx1.h"
extern "C" void abort (void);

void
check (A *x, B *y)
{
  C d;
  if (x->b () != 21)
    abort ();
  if (y->B::a () != 22)
    abort ();
  if (d.a () != 23)
    abort ();
  if (d.C::b () != 24)
    abort ();
}

int
main ()
{
  A x;
  if (x.a () != 20)
    abort ();
  do_check (check, &x);
  return 0;
}
