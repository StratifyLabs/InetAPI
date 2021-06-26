cmake_minimum_required (VERSION 3.12)

if(NOT SOS_SDK_PATH)
	set(SOS_SDK_PATH $ENV{SOS_SDK_PATH})
endif()

set(CMAKE_MODULE_PATH ${SOS_SDK_PATH}/cmake)
set(CMAKE_TOOLCHAIN_FILE ${CMAKE_MODULE_PATH}/sos-toolchain.cmake)
include(sos-sdk)

project(InetAPI CXX)

if(NOT DEFINED API_IS_SDK)
	include(API)
endif()

set(LWIP_VERSION "2.1.2" CACHE INTERNAL "Effective LWIP version")

option(IS_MBEDTLS "Build mbedtls" ON)
option(IS_LWIP "Build lwip" ON)

if(SOS_IS_ARM AND IS_LWIP)
	add_subdirectory(lwip lwip)
endif()

if(IS_MBEDTLS)
	#add_subdirectory(mbedtls mbedtls)
endif()
#add_subdirectory(library library)
if(SOS_IS_TEST)
	#add_subdirectory(tests tests)
endif()
