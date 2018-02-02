#define CVDEBUG
#pragma once
#include "opencv2/core/core.hpp"
#include "opencv2/imgproc/imgproc.hpp"
#include "opencv2/highgui/highgui.hpp"
#include <iostream>
using namespace std;
using namespace cv;

#ifdef CVDEBUG
const string DATA_PATH = "../../../../../data/";
#else
const string DATA_PATH = "../../../data/";
#endif

// read image using image name
Mat LoadImage(const string img_name)
{
    Mat img = imread(DATA_PATH + img_name);
    if (img.empty())
    {
        cout << "��ͼ��ʧ�ܣ�" << endl;
        getchar();
        exit(0);
    }
    return img;
}
