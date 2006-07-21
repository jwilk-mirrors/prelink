int var = 24, var2 = 16;

int varp1 (void)
{
  return var + 1;
}

int var2m1 (void)
{
  return var2 - 1;
}

int bar (void)
{
  return varp1 () + var2m1 () + 1;
}
