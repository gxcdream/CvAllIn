INCLUDE_DIRECTORIES(${CvAllIn_SOURCE_DIR}/dep/opencv331/include 
                    ${CvAllIn_SOURCE_DIR}/dep/opencv331/include/opencv2
                    ${CvAllIn_SOURCE_DIR}/dep/opencv331/include/opencv)

LINK_DIRECTORIES(${CvAllIn_SOURCE_DIR}/dep/opencv331/lib) 


set(HEADER_FILES stdafx.h)
# Add the source file directory
aux_source_directory(. Tracking_srcs)

ADD_EXECUTABLE(OpticFlowAPI ${Tracking_srcs} stdafx.h)
TARGET_LINK_LIBRARIES(OpticFlowAPI
opencv_core331d
opencv_highgui331d
opencv_imgproc331d
opencv_optflow331d
opencv_tracking331d
opencv_video331d
opencv_videoio331d
opencv_videostab331d)


## Add header file include directories
# INCLUDE_DIRECTORIES(./)
## Add block directories
#add_subdirectory(hello)
#add_subdirectory(world)
## Target
#add_executable(helloworld ${DIRSRCS})
#target_link_libraries(helloworld hello world)