#include "tls1.h"
#include <stdlib.h>

asm (".section trampoline, \"awx\"; .previous");

#if !defined __sparc__ || defined __pic__ || defined __PIC__
#define ieattr __attribute__((tls_model("initial-exec")))
#else
#define ieattr
#endif

static __thread long long dummy = 12;
__thread struct A a2 = { 22, 23, 24 };
__thread struct A a4 ieattr = { 25, 26, 27 };
static __thread struct A local1 = { 28, 29, 30 };
static __thread struct A local2 ieattr = { 31, 32, 33 };

void __attribute__((section ("trampoline"))) check2 (void)
{
  if (a2.a != 22 || a2.b != 23 || a2.c != 24)
    abort ();
  if (a4.a != 25 || a4.b != 26 || a4.c != 27)
    abort ();
  if (local1.a != 28 || local1.b != 29 || local1.c != 30)
    abort ();
  if (local2.a != 31 || local2.b != 32 || local2.c != 33)
    abort ();
}

struct A * __attribute__((section ("trampoline"))) f7a (void)
{
  return &a2;
}

struct A * __attribute__((section ("trampoline"))) f8a (void)
{
  return &a4;
}

struct A * __attribute__((section ("trampoline"))) f9a (void)
{
  return &local1;
}

struct A * __attribute__((section ("trampoline"))) f10a (void)
{
  return &local2;
}

int __attribute__((section ("trampoline"))) f7b (void)
{
  return a2.b;
}

int __attribute__((section ("trampoline"))) f8b (void)
{
  return a4.a;
}

int __attribute__((section ("trampoline"))) f9b (void)
{
  return local1.b;
}

int __attribute__((section ("trampoline"))) f10b (void)
{
  return local2.c;
}
