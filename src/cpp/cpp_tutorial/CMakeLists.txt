# set(HEADER_FILES stdafx.h)
# Add the source file directory
aux_source_directory(. tutorial_srcs)
ADD_EXECUTABLE(cpp_tutorial ${tutorial_srcs})