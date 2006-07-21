#include "reloc1.h"
#include <stdlib.h>
#include <stdio.h>

int i;
int j __attribute__((aligned (32)));
int k[2048];
int l = 26;

void f5 (FILE *f)
{
  fprintf (stdout, "OK");
}

int main()
{
  struct A *x;
  foo.c -= 2;
  if (foo.a != 1 || foo.b != &foo || foo.c[0] != 28 || foo.c[1] != 29
      || foo.c[2] != 30)
    abort ();
  if (f1 () != 11 || f2 () != 12)
    abort ();
  x = f3 ();
  if (x->a != 2 || x->b != x || x->c != foo.c + 1)
    abort ();
  f5 (stdout);
  exit (0);
}
