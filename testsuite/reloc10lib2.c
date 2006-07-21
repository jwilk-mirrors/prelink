extern int bar, baz, f1 (void), f2 (void);

int f3 (void)
{
  return f1 () + 3;
}

int f4 (void)
{
  return f2 () + 4;
}
