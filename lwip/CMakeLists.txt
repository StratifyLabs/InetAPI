cmake_minimum_required (VERSION 3.12)

project(lwip CXX C)

sos_sdk_library_target(RELEASE ${PROJECT_NAME} "${LIB_OPTION}" release ${SOS_ARCH})

sos_sdk_add_subdirectory(PRIVATE_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/src)
sos_sdk_add_subdirectory(INTERFACE_SOURCES include)

add_library(${RELEASE_TARGET} STATIC)

set_property(TARGET ${RELEASE_TARGET} PROPERTY CXX_STANDARD 17)

target_sources(${RELEASE_TARGET}
	PRIVATE
	${INTERFACE_SOURCES}
	${PRIVATE_SOURCES}
	${CMAKE_CURRENT_SOURCE_DIR}/${PROJECT_NAME}.cmake
	)

target_include_directories(${RELEASE_TARGET}
	PUBLIC
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

install(FILES ${PROJECT_NAME}.cmake
	DESTINATION cmake/targets)



