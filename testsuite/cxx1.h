struct A
  {
    virtual int a ();
    virtual int b ();
    int c;
  };
struct B
  {
    virtual int a ();
    int b;
  };
struct C
  {
    virtual int a ();
    virtual int b ();
    int c;
  };

void do_check (void (*check) (A *x, B *y), A *x);
