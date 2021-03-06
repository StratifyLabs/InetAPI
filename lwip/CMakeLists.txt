cmake_minimum_required (VERSION 3.12)

project(lwip CXX C)


# Copy lwipopts_template.h if lwipopts.h is missing
if(NOT EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/include/lwipopts.h)
	file(READ
		${CMAKE_CURRENT_SOURCE_DIR}/include/lwipopts_template.h
		LWIPOPTS_TEMPLATE)
	file(WRITE
		${CMAKE_CURRENT_SOURCE_DIR}/include/lwipopts.h
		${LWIPOPTS_TEMPLATE}
		)
endif()


sos_sdk_library_target(RELEASE ${PROJECT_NAME} "${LIB_OPTION}" release ${SOS_ARCH})
sos_sdk_add_subdirectory(PRIVATE_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/src)
sos_sdk_add_subdirectory(INTERFACE_SOURCES include)

add_library(${RELEASE_TARGET} STATIC)

set(LWIP_VERSION "2.1.2")

target_sources(${RELEASE_TARGET}
	PRIVATE
	${INTERFACE_SOURCES}
	${PRIVATE_SOURCES}
	${CMAKE_CURRENT_SOURCE_DIR}/${PROJECT_NAME}.cmake
	)

target_include_directories(${RELEASE_TARGET}
	PUBLIC
	$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/lwip-${LWIP_VERSION}/src/include>
	$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
	PRIVATE
	)

sos_sdk_library_target(DEBUG ${PROJECT_NAME} "${LIB_OPTION}" debug ${SOS_ARCH})
add_library(${DEBUG_TARGET} STATIC)
sos_sdk_copy_target(${RELEASE_TARGET} ${DEBUG_TARGET})

target_compile_options(${RELEASE_TARGET}
	PRIVATE
	-Os
	)

target_compile_options(${DEBUG_TARGET}
	PRIVATE
	-Os
	)

sos_sdk_library_add_arch_targets("${DEBUG_OPTIONS}" ${SOS_ARCH} "")
sos_sdk_library_add_arch_targets("${RELEASE_OPTIONS}" ${SOS_ARCH} "")

install(DIRECTORY include/
	DESTINATION include/${PROJECT_NAME}
	PATTERN CMakelists.txt EXCLUDE)

install(DIRECTORY lwip-${LWIP_VERSION}/src/include/lwip/
	DESTINATION include/${PROJECT_NAME}
	PATTERN CMakelists.txt EXCLUDE)

install(FILES ${PROJECT_NAME}.cmake
	DESTINATION ${SOS_SDK_PATH}/cmake/targets)

