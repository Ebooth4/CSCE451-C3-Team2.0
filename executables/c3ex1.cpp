#include<iostream>

using namespace std;

int function1 (int param1, int param2) {
  int* a = new int(4); // goes into d

  int* b = new int(5); // goes into c
  int* c = new int(6); // goes into output
  *c += *b;

  int* d = new int(param1 + param2); // goes into 
  *d += *a;

  int* e = new int(7); // goes into f
  int* f = new int(8); // useless
  *f *= *e;

  cout << "function1 output: " << *c << endl;

  return *d;
}

int function2 (int param1, int param2) {
  int a = 4; // goes into d

  int b = 5; // goes into c
  int c = 6; // goes into output
  c += b;

  int d = param1 + param2; // goes into 
  d += a;

  int e = 7; // goes into f
  int f = 8; // useless
  f *= e;

  cout << "function2 output: " << c << endl;

  return d;
}

int main() {
  int a = function1(2, 3);
  cout << "function1 return: " << a << endl;
  int b = function2(2, 3);
  cout << "function2 return: " << b << endl;
}