#include "cxx1.h"

int A::a ()
{
  return 10;
}

int A::b ()
{
  return 11;
}

int B::a ()
{
  return 12;
}

int C::a ()
{
  return 13;
}

int C::b ()
{
  return 14;
}

void
do_check (void (*check) (A *x, B *y), A *x)
{
  B y;

  check (x, &y);
}
