### path for header files
INCLUDE_DIRECTORIES(.)

INCLUDE_DIRECTORIES(${CvAllIn_SOURCE_DIR}/dep/opencv331/include)
INCLUDE_DIRECTORIES(${CvAllIn_SOURCE_DIR}/dep/opencv331/include/opencv2)
INCLUDE_DIRECTORIES(${CvAllIn_SOURCE_DIR}/dep/opencv331/include/opencv)
INCLUDE_DIRECTORIES(${CvAllIn_SOURCE_DIR}/dep/eigen3)

### path for lib files
LINK_DIRECTORIES(${CvAllIn_SOURCE_DIR}/dep/freeglut/lib)
LINK_DIRECTORIES(${CvAllIn_SOURCE_DIR}/dep/opencv331/lib) 

### projects ###
#ADD_SUBDIRECTORY(common)
# ADD_SUBDIRECTORY(nonlinear_optimization)
# ADD_SUBDIRECTORY(Tracking)
ADD_SUBDIRECTORY(cpp_tutorial)
# ADD_SUBDIRECTORY(encrypt)
ADD_SUBDIRECTORY(opencv_quickdemo)
