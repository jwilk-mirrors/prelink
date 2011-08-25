struct A
  {
    virtual int a () { return 1; }
    virtual int b () { return 2; }
    virtual ~A () {}
    int c;
  };
struct B
  {
    virtual int a () { return 3; }
    virtual ~B () {}
    int b;
  };
struct C
  {
    virtual int a () { return 4; }
    virtual int b () { return 5; }
    virtual ~C () {}
    int c;
  };

void do_check (void (*check) (A *x, B *y), A *x);
