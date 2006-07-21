#ifndef D1
#define D1(n) int qvar##n; int *qpvar##n = &qvar##n;
#endif
#define D2(n) D1(n##0) D1(n##1) D1(n##2) D1(n##3) D1(n##4)
#define D3(n) D2(n##0) D2(n##1) D2(n##2) D2(n##3) D2(n##4)
#define D4(n) D3(n##0) D3(n##1) D3(n##2) D3(n##3) D3(n##4)
D4(0) D4(1)
