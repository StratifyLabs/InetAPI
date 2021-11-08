cmake_minimum_required (VERSION 3.12)

project(InetAPI CXX)

set(LWIP_VERSION "2.1.2" CACHE INTERNAL "Effective LWIP version")

option(IS_MBEDTLS "Build mbedtls" ON)
option(IS_LWIP "Build lwip" ON)

if(SOS_IS_ARM AND IS_LWIP)
	add_subdirectory(lwip lwip)
endif()

if(IS_MBEDTLS)
	add_subdirectory(mbedtls mbedtls)
endif()
add_subdirectory(library library)

option(INET_API_IS_TEST "Enable test build for InetAPI" OFF)
if(INET_API_IS_TEST)
	add_subdirectory(tests tests)
endif()
