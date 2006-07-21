#include "deps1.h"

int bar = 26;
int baz = 28;

struct A foo = { 1, &foo, &bar };

int f0 (void)
{
  return f1 () + f2 () + f9 () + bar + baz;
}

int f1 (void)
{
  return 1;
}

int f2 (void)
{
  return f1 () + 1;
}

int f9 (void)
{
  return 18;
}
