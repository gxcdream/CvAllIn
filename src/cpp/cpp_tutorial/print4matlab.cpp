#include "mex.h"
#include <iostream>

using namespace std;
void mexFunction(int nlhs, mxArray *plhs[], int nrhs, const mxArray *prhs[])
{
    //if (nrhs != 1)
    //    mexErrMsgTxt("Wrong number of input arguments.\n"); // ���������������Ƿ���ȷ�����򱨴� 
    //if (nlhs > 1) mexErrMsgTxt("Too many output argumnents.\n"); // ���������������Ƿ���ȷ�����򱨴� 

    cout << "using std cout" << endl;
    mexPrintf("using mexPrintf\n");
}

#ifdef test_main
int main()
{
    cout << "print4matlab" << endl;

    return 0;
}
#endif