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
#else
# error Architecture not supported
#endif
#define IFUNC(name, hidden, fn1, fn2) \
extern __typeof (fn1) fn1 __attribute__((used));	\
extern __typeof (fn2) fn2 __attribute__((used));	\
extern __typeof (fn1) name;				\
asm (".globl " #name "\n"				\
     "\t" hidden " " #name "\n"				\
     "\t.type " #name ", @gnu_indirect_function\n"	\
     #name ":\n"					\
     IFUNC_ASM (PICK (fn1, fn2))			\
     "\t.size " #name ", .-" #name "\n")
#define IFUNC_LOCAL(name, fn1, fn2) IFUNC(name, ".hidden", fn1, fn2)
#define IFUNC_GLOBAL(name, fn1, fn2) IFUNC(name, ".globl", fn1, fn2)
