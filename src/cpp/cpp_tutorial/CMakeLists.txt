# matlab mex include path
INCLUDE_DIRECTORIES(${CvAllIn_SOURCE_DIR}/dep/matlab_extern/include)

### path for lib files
LINK_DIRECTORIES(${CvAllIn_SOURCE_DIR}/dep/matlab_extern/lib/win64/microsoft)

ADD_SUBDIRECTORY(visual_studio_with_matlab)

# set(HEADER_FILES stdafx.h)
# Add the source file directory
# aux_source_directory(. tutorial_srcs)
# aux_source_directory(visual_studio_with_matlab tutorial_srcs)

# ADD_EXECUTABLE(cpp_tutorial ${tutorial_srcs})
# ADD_EXECUTABLE(cpp_tutorial print4matlab.cpp)

# ADD_EXECUTABLE(cpp_tutorial MLenginedemo.cpp gaussian3x3.cpp gaussian3x3.h)