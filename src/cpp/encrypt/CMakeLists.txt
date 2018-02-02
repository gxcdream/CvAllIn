# include_directories(../)
# AUX_SOURCE_DIRECTORY(. ENCRYPT_SRC)
# ADD_LIBRARY(encrypt ${ENCRYPT_SRC})
ADD_LIBRARY(encrypt encrypt.h encrypt.cpp)

ADD_EXECUTABLE(encrypt_test encrypt_test.cpp)
TARGET_LINK_LIBRARIES(encrypt_test encrypt)