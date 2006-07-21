#include "tls1.h"
#include <stdlib.h>

static __thread int dummy;
__thread struct A local;

int main()
{
  exit (dummy + local.a + local.b + local.c);
}
