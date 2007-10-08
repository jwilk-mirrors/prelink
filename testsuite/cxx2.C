#include "cxx1.h"
extern "C" void abort (void);

int A::a ()
{
  return 30;
}

int A::b ()
{
  return 31;
}

int B::a ()
{
  return 32;
}

int C::a ()
{
  return 33;
}

int C::b ()
{
  return 34;
}

void
check (A *x, B *y)
{
  C d;
  if (x->b () != 31)
    abort ();
  if (y->B::a () != 32)
    abort ();
  if (d.a () != 33)
    abort ();
  if (d.C::b () != 34)
    abort ();
}

int
main ()
{
  A x;
  if (x.a () != 30)
    abort ();
  do_check (check, &x);
  return 0;
}
