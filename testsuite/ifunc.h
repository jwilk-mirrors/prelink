#ifndef PICKNO
# define PICKNO 1
#endif
#if PICKNO == 2
# define PICK(fn1, fn2) #fn2
#else
# define PICK(fn1, fn2) #fn1
#endif
#ifdef __x86_64__
# define IFUNC_ASM(fn) "\tleaq " fn "(%rip), %rax\n\tretq\n"
#elif defined __i386__
# ifdef __PIC__
#  define IFUNC_ASM(fn) "\tcall 1f\n1:\tpopl %ecx\n"	\
    "\taddl $_GLOBAL_OFFSET_TABLE_+[.-1b], %ecx\n"	\
    "\tleal " fn "@GOTOFF(%ecx), %eax\n\tret\n"
# else
#  define IFUNC_ASM(fn) "\tmovl $" fn ", %eax\n\tret\n"
# endif
#elif defined __powerpc__
# define IFUNC_ASM(fn) "\tmflr 12\n\tbcl 20,31,1f\n"	\
    "\t1:mflr 3\n\tmtlr 12\n\taddis 3,3, " fn		\
    "-1b@ha\n\taddi 3,3," fn "-1b@l\n\tblr\n"
# if defined __powerpc64__
#  define IFUNC_DECL(name, hidden, fn1, fn2) \
asm (".text\n"						\
     "\t.globl " #name "\n"				\
     "\t" hidden " " #name "\n"				\
     "\t.type " #name ", @gnu_indirect_function\n"	\
     "\t.section .opd,\"aw\"\n"				\
     "\t.align 3\n"					\
     #name ":\n"					\
     "\t.quad .L." #name ",.TOC.@tocbase,0\n"		\
     "\t.previous\n"					\
     ".L." #name ":\n"					\
     IFUNC_ASM (PICK (fn1, fn2))			\
     "\t.size " #name ", .-.L" #name "\n")
# endif
#elif defined __s390x__
# define IFUNC_ASM(fn) "\tlarl %r2," fn "\n"		\
    "\tbr %r14\n"
#elif defined __s390__
# define IFUNC_ASM(fn) "\t"				\
    "\tst %r12,48(%r15)\n"				\
    "\tbasr %r5,0\n"					\
  "1:\tl %r12,3f-1b(%r5)\n"				\
    "\tl %r1,2f-1b(%r5)\n"				\
    "\tla %r12,0(%r12,%r5)\n"				\
    "\tla %r2,0(%r1,%r12)\n"				\
    "\tl %r12,48(%r15)\n"				\
    "\tbr %r14\n"					\
    "\t.align 4\n"					\
  "2:\t.long " fn "@GOTOFF\n"				\
  "3:\t.long _GLOBAL_OFFSET_TABLE_-1b\n"
#else
# error Architecture not supported
#endif
#ifndef IFUNC_DECL
#define IFUNC_DECL(name, hidden, fn1, fn2) \
asm (".text\n"						\
     "\t.globl " #name "\n"				\
     "\t" hidden " " #name "\n"				\
     "\t.type " #name ", @gnu_indirect_function\n"	\
     #name ":\n"					\
     IFUNC_ASM (PICK (fn1, fn2))			\
     "\t.size " #name ", .-" #name "\n")
#endif
#define IFUNC(name, hidden, fn1, fn2) \
extern __typeof (fn1) fn1 __attribute__((used));	\
extern __typeof (fn2) fn2 __attribute__((used));	\
extern __typeof (fn1) name;				\
IFUNC_DECL (name, hidden, fn1, fn2)
#define IFUNC_LOCAL(name, fn1, fn2) IFUNC(name, ".hidden", fn1, fn2)
#define IFUNC_GLOBAL(name, fn1, fn2) IFUNC(name, ".globl", fn1, fn2)
