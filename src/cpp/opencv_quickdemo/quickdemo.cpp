//#define CVDEBUG
#include "common/header.h"

int main()
{
    string img_name = "lenaColor.jpg";
    Mat img = LoadImage(img_name);

    //namedWindow("image", CV_WINDOW_AUTOSIZE);
    imshow("image", img);
    waitKey(1);
    return 0;
}