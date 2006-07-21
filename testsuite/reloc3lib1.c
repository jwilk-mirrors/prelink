#include "reloc1.h"

int baz[3] = { 28, 29, 30 };

struct A foo = { 1, &foo, &baz[2] };
static struct A xfoo = { 2, &xfoo, &baz[1] };

int f1 (void)
{
  return 1;
}

int f2 (void)
{
  return f1 () + 1;
}

struct A *f3 (void)
{
  return &xfoo;
}
