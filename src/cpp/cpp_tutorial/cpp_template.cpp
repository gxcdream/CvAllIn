//#include "common/header.h"

#include <iostream>
using namespace std;
// template function
//template <typename T>
template <class T>
T SumTwo(const T op1, const T op2)
{
    return op1 + op2;
}

int main()
{
    int a=1, b=2, c;
    c = SumTwo(a, b);
    cout << "int result = " << c << endl;
    
    double ad=1.1, bd=2.4, cd;
    cd = SumTwo(ad, bd);
    cout << "double result = " << cd << endl;

    //getchar();
    return 0;
}