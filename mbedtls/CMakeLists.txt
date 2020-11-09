


set(MBEDTLS_GIT_REPOSITORY "https://github.com/ARMmbed/mbedtls.git")
set(MBEDTLS_BRANCH "mbedtls-2.16")

if(NOT EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/mbedtls/library)
	message(STATUS "Need to clone manually for the first call to cmake")
	execute_process(
		COMMAND git clone --branch ${MBEDTLS_BRANCH} ${MBEDTLS_GIT_REPOSITORY}
		WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
		)
	file(REMOVE ${CMAKE_CURRENT_SOURCE_DIR}/mbedtls/include/mbedtls/config.h)
	file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/config/mbedtls/config.h DESTINATION ${CMAKE_CURRENT_SOURCE_DIR}/mbedtls/include/mbedtls)
endif()

file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/config/mbedtls/config.h DESTINATION ${CMAKE_CURRENT_SOURCE_DIR}/mbedtls/include/mbedtls)

project(mbedtls CXX C)

set(SOS_DEFINITIONS IS_LOCAL_BUILD=1)
set(SOS_INCLUDE_DIRECTORIES ${CMAKE_CURRENT_SOURCE_DIR}/config/mbedtls mbedtls/include ${CMAKE_CURRENT_SOURCE_DIR})

install(DIRECTORY mbedtls/include/mbedtls DESTINATION include)
install(FILES mbedtls_api.h mbedtls_link_config.h mbedtls_sos_config.h DESTINATION include)

include(${CMAKE_CURRENT_SOURCE_DIR}/sources.cmake)

set(FORMAT_SOURCELIST
	mbedtls_api.h
	mbedtls_api.c
	mbedtls_crypt_api.c
	)

set(PRIVATE_SOURCELIST
	${TLS_SOURCES}
	${X509_SOURCES}
	${SOURCES}
	${HEADERS}
	${FORMAT_SOURCELIST}
	config/mbedtls/config.h
	net_sockets.c
	timing_alt.h
	threading.c)

set(SOS_OPTION kernel)
set(SOS_DEFINITIONS ${SOS_DEFINITIONS} -DHAVE_LWIP_SOCKETS_H)

if(SOS_IS_ARM)
	set(LIB_OPTION kernel)
	list(APPEND PRIVATE_SOURCELIST mbedtls_sos_config.h)
else()
	list(APPEND PRIVATE_SOURCELIST mbedtls_link_config.h)
endif()

sos_sdk_library_target(RELEASE mbedtls "${LIB_OPTION}" release ${SOS_ARCH})

add_library(${RELEASE_TARGET} STATIC)

target_sources(${RELEASE_TARGET}
	PUBLIC
	${PUBLIC_SOURCES}
	PRIVATE
	${PRIVATE_SOURCELIST}
	)

target_compile_definitions(${RELEASE_TARGET}
	PUBLIC
	${SOS_DEFINITIONS}
	PRIVATE
	IS_LOCAL_BUILD=1
	)

target_include_directories(${RELEASE_TARGET}
	PUBLIC
	$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
	PRIVATE
	${SOS_INCLUDE_DIRECTORIES}
	)


sos_sdk_library_target(DEBUG mbedtls "${LIB_OPTION}" debug ${SOS_ARCH})
add_library(${DEBUG_TARGET} STATIC)
sos_sdk_copy_target(${RELEASE_TARGET} ${DEBUG_TARGET})
sos_sdk_library_add_arch_targets("${DEBUG_OPTIONS}" ${SOS_ARCH} "")

if(SOS_IS_LINK)
	sos_sdk_library_target(COVERAGE mbedtls "${LIB_OPTION}" coverage ${SOS_ARCH})
	add_library(${COVERAGE_TARGET} STATIC)
	sos_sdk_copy_target(${RELEASE_TARGET} ${COVERAGE_TARGET})

	target_compile_options(${COVERAGE_TARGET}
		PUBLIC
		--coverage
		)

	sos_sdk_library_add_arch_targets("${COVERAGE_OPTIONS}" ${SOS_ARCH} "")
endif()

sos_sdk_library_add_arch_targets("${RELEASE_OPTIONS}" ${SOS_ARCH} "")

target_compile_options(${RELEASE_TARGET}
	PUBLIC
	-Os
	)

target_compile_options(${DEBUG_TARGET}
	PUBLIC
	-Os
	)

add_custom_target(
	${API_NAME}_format
	COMMAND /usr/local/bin/clang-format
	-i
	--verbose
	${FORMAT_LIST}
	)


