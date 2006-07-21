#include "tls1.h"
#include <stdlib.h>

#define CHECK(N, S)					\
  p = f##N##a ();					\
  if (p->a != S || p->b != S + 1 || p->c != S + 2)	\
    abort ()

int main()
{
  struct A *p;
  check1 ();
  check2 ();
  CHECK (1, 4);
  CHECK (2, 22);
  CHECK (3, 10);
  CHECK (4, 25);
  CHECK (5, 16);
  CHECK (6, 19);
  CHECK (7, 22);
  CHECK (8, 25);
  CHECK (9, 28);
  CHECK (10, 31);
  exit (0);
}
