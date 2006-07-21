#include "reloc1.h"
#include <stdlib.h>

#define M(i) int b##i; extern *pb##i;
M(0) M(1) M(2) M(3) M(4) M(5) M(6) M(7) M(8) M(9)
M(10) M(11) M(12) M(13) M(14) M(15) M(16) M(17) M(18) M(19)
#undef M

int f1 (void)
{
#define M(i) if (pb##i != &b##i) abort ();
M(0) M(1) M(2) M(3) M(4) M(5) M(6) M(7) M(8) M(9)
M(10) M(11) M(12) M(13) M(14) M(15) M(16) M(17) M(18) M(19)
#undef M
  return 11;
}
