#include <stdio.h>

int main (void)
{
  int i, j;

  for (i = 0; i < 256; ++i)
    {
      printf ("extern int ");
      for (j = 0; j < 255; ++j)
	printf ("foo%02x%02x (void), ", i, j);
      printf ("foo%02xff (void);\nint bar%02x (int x) { return x", i, i);
      for (j = 0; j < 256; ++j)
	printf (" + foo%02x%02x ()", i, j);
      printf ("; }\n");
    }
}
