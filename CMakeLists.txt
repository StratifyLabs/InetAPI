cmake_minimum_required (VERSION 3.12)

project(InetAPI
	LANGUAGES CXX
	VERSION 1.5.2)

set(LWIP_VERSION "2.1.2" CACHE INTERNAL "Effective LWIP version")

option(INET_API_IS_MBEDTLS "Build mbedtls" ON)
option(INET_API_IS_LWIP "Build lwip" ON)
option(INET_API_HAS_STRATIFY_OS "Link build has access to Stratify OS header files" OFF)

if(CMSDK_IS_ARM AND INET_API_IS_LWIP)
	add_subdirectory(lwip lwip)
endif()

if(INET_API_IS_MBEDTLS)
	add_subdirectory(mbedtls mbedtls)
endif()
add_subdirectory(library library)

option(INET_API_IS_TEST "Enable test build for InetAPI" OFF)
if(INET_API_IS_TEST)
	add_subdirectory(tests tests)
endif()
