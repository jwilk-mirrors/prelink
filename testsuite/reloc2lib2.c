extern int f1 (int dummy);

int f2 (int add)
{
  if (add)
    return f1 (0) + 26;
  return f1 (0);
}

/* Make sure conflict in f3 is not against read-only segment.  */
asm (".section trampoline, \"awx\"; .previous");
void * __attribute__((section ("trampoline"))) f3 (void)
{
  return (void *) f3;
}
