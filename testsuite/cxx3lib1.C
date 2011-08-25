#include "cxx3.h"

A a1;
B b1;
C c1;

void
do_check (void (*check) (A *x, B *y), A *x)
{
  B y;

  check (x, &y);
}
