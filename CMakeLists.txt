cmake_minimum_required (VERSION 3.12)

if(NOT SOS_SDK_PATH)
	set(SOS_SDK_PATH $ENV{SOS_SDK_PATH})
endif()

set(CMAKE_MODULE_PATH ${SOS_SDK_PATH}/Tools/gcc/cmake)
set(CMAKE_TOOLCHAIN_FILE ${CMAKE_MODULE_PATH}/sos-toolchain.cmake)
include(sos-sdk)

project(InetAPI CXX)

if(NOT DEFINED IS_SDK)
	include(API)
endif()


add_subdirectory(lwip lwip)
add_subdirectory(mbedtls mbedtls)
add_subdirectory(library library)
add_subdirectory(tests tests)
