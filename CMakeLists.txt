cmake_minimum_required (VERSION 3.12)

if(NOT SOS_SDK_PATH)
	set(SOS_SDK_PATH $ENV{SOS_SDK_PATH})
endif()

set(CMAKE_MODULE_PATH ${SOS_SDK_PATH}/cmake)
set(CMAKE_TOOLCHAIN_FILE ${CMAKE_MODULE_PATH}/sos-toolchain.cmake)
include(sos-sdk)

project(InetAPI CXX)

set(SOS_ARCH v7em_f5dh)
set(SOS_ARCH_LIST "")

if(NOT DEFINED API_IS_SDK)
	include(API)
endif()

OPTION(IS_MBEDTLS ON)
OPTION(IS_LWIP ON)
OPTION(IS_TESTS ON)

if(SOS_IS_ARM)
	if(ON)
		add_subdirectory(lwip lwip)
	endif()
endif()

if(IS_MBEDTLS)
	add_subdirectory(mbedtls mbedtls)
endif()
add_subdirectory(library library)
if(IS_TESTS)
	add_subdirectory(tests tests)
endif()
