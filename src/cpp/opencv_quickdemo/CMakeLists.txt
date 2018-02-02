#set(HEADER_FILES stdafx.h)
# Add the source file directory
aux_source_directory(. quickdemo)

ADD_EXECUTABLE(quickdemo ${quickdemo} ${HEADER_FILES})
TARGET_LINK_LIBRARIES(quickdemo
opencv_core331d
opencv_highgui331d
opencv_imgproc331d
opencv_imgcodecs331d
)

