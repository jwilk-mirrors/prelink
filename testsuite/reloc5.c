#include <stdio.h>

int main (void)
{
  int i;

  printf ("#include <stdlib.h>\nextern char testzero[16384];\nextern int");
  for (i = 0; i < 255; ++i)
    printf (" bar%02x (int),", i);
  printf (" barff (int);\nint main (void)\n{\n  int x = 0;\n");
  for (i = 0; i < 256; ++i)
    printf ("  x = bar%02x (x);\n", i);
  printf ("  if (x != 0x7fff8000) abort ();\n");
  printf ("  for (x = 0; x < 16384; ++x)\n");
  printf ("    if (testzero[x]) abort ();\n");
  printf ("  exit (0);\n}\n\n");
  printf ("asm (\".section nonalloced,\\\"aw\\\",@nobits\\n\\t\"\n");
  printf ("     \".globl testzero\\n\\t\"\n");
  printf ("     \"testzero: .skip 16384\\n\\t\"\n");
  printf ("     \".previous\");\n");
}
