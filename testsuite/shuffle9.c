#include "reloc1.h"
#include <stdlib.h>

extern char testzero[16384];

int main()
{
  int i;
  if (foo.a != 1 || foo.b != &foo || foo.c != &bar || bar != 26)
    abort ();
  if (f1 () != 11 || f2 () != 12)
    abort ();
  for (i = 0; i < 16384; ++i)
    if (testzero[i])
      abort ();
  exit (0);
}

asm (".section nonalloced,\"aw\",@nobits\n\t"
     ".globl testzero\n\t"
     "testzero: .skip 16384\n\t"
     ".previous\n");

asm (".section \".note.PRELINK.1\", \"a\"\n\t"
     ".balign 4\n\t"
     ".long 1f - 0f\n\t"
     ".long 3f - 2f\n\t"
     ".long 1\n"
 "0:\t.asciz \"PRELINK\"\n"
 "1:\t.balign 4\n"
 "2:\t.long 12\n\t"
     ".long 17\n"
 "3:\t.balign 4\n\t"
     ".previous\n");

asm (".section \".note.PRELINK.2\", \"a\"\n\t"
     ".balign 4\n\t"
     ".long 1f - 0f\n\t"
     ".long 3f - 2f\n\t"
     ".long 2\n"
 "0:\t.asciz \"PRELINK\"\n"
 "1:\t.balign 4\n"
 "2:\t.long 12\n\t"
     ".long 17\n"
 "3:\t.balign 4\n\t"
     ".previous\n");

asm (".section \".note.PRELINK.3\", \"a\"\n\t"
     ".balign 4\n\t"
     ".long 1f - 0f\n\t"
     ".long 3f - 2f\n\t"
     ".long 3\n"
 "0:\t.asciz \"PRELINK\"\n"
 "1:\t.balign 4\n"
 "2:\t.long 12\n\t"
     ".long 17\n"
 "3:\t.balign 4\n\t"
     ".previous\n");
