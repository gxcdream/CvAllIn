# Add the source file directory
aux_source_directory(. NONOPI_SRCS)

ADD_EXECUTABLE(nonlinear_optimization ${NONOPI_SRCS})
# TARGET_LINK_LIBRARIES(nonlinear_optimization opencv_world331d)
TARGET_LINK_LIBRARIES(nonlinear_optimization
opencv_core331d
opencv_highgui331d
opencv_imgproc331d
opencv_imgcodecs331d)