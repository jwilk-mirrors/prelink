#include <stdio.h>

int main (void)
{
  int i;

  printf ("#include <stdlib.h>\nextern int");
  for (i = 0; i < 255; ++i)
    printf (" bar%02x (int),", i);
  printf (" barff (int);\nint main (void)\n{\n  int x = 0;\n");
  for (i = 0; i < 256; ++i)
    printf ("  x = bar%02x (x);\n", i);
  printf ("  if (x != 0x7fff8000) abort ();\n  exit (0);\n}\n");
}
