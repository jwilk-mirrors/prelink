#include "reloc1.h"
#include <stdlib.h>
#include <stdio.h>

int i;
int j __attribute__((aligned (32)));
int k[2048];
int l = 26;
int m[3] = { 28, 29, 30 };
extern int baz[3];

struct A n __attribute__((section("nsec"))) = { 1, &n, &m[2] };
static struct A o __attribute__((section("osec"))) = { 2, &o, &baz[1] };

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
  if (n.a != 1 || n.b != &n || n.c != m + 2)
    abort ();
  if (o.a != 2 || o.b != &o || o.c != baz + 1)
    abort ();
  f5 (stdout);
  exit (0);
}
