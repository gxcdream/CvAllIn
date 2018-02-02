rd /s /q build
mkdir build
cd build

mkdir win32

cd win32
cmake -G "Visual Studio 11 2012" ..\..

Rem cd ..\win64
Rem cmake -G "Visual Studio 11 2012 Win64"   ..\..

cd ..\..

rd /s /q bin\lib\Debug
Rem mkdir bin
xcopy /r /y dep\opencv331\dll\opencv_core331d.dll bin\lib\Debug\
xcopy /r /y dep\opencv331\dll\opencv_imgproc331d.dll bin\lib\Debug\
xcopy /r /y dep\opencv331\dll\opencv_highgui331d.dll bin\lib\Debug\
xcopy /r /y dep\opencv331\dll\opencv_imgcodecs331d.dll bin\lib\Debug\
pause