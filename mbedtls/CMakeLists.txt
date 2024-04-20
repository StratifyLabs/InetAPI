set(MBEDTLS_GIT_REPOSITORY "https://github.com/ARMmbed/mbedtls.git")
set(MBEDTLS_BRANCH "mbedtls-2.28")
if(NOT EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/mbedtls)
  message(STATUS "Need to clone manually for the first call to cmake")
  execute_process(
    COMMAND git clone --depth 1 --branch ${MBEDTLS_BRANCH} ${MBEDTLS_GIT_REPOSITORY}
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
  )
endif()
project(mbedtls CXX C)
set(LWIP_VERSION "2.1.2")
if(NOT MBEDTLS_CONFIG_FILE)
  message(FATAL_ERROR "MBEDTLS_CONFIG_FILE must be set")
endif()
get_filename_component(MBEDTLS_CONFIG_FILE_PATH ${MBEDTLS_CONFIG_FILE} DIRECTORY)
if(NOT EXISTS ${MBEDTLS_CONFIG_FILE_PATH})
  message(FATAL_ERROR "Could not find path to mbedtls config file ${MBEDTLS_CONFIG_FILE}")
endif()
message(STATUS "Including path to mbedtls config: ${MBEDTLS_CONFIG_FILE_PATH}")
install(DIRECTORY mbedtls/include/mbedtls DESTINATION include)
install(FILES mbedtls_api.h mbedtls_link_config.h mbedtls_sos_config.h DESTINATION include)
include(${CMAKE_CURRENT_SOURCE_DIR}/sources.cmake)
set(FORMAT_SOURCELIST
  mbedtls_api.h
  mbedtls_api.c
  mbedtls_crypt_aes_api.c
  mbedtls_crypt_ecc_api.c
  mbedtls_crypt_sha_api.c
  mbedtls_crypt_random_api.c)
set(PRIVATE_SOURCELIST
  ${TLS_SOURCES}
  ${X509_SOURCES}
  ${SOURCES}
  ${HEADERS}
  ${FORMAT_SOURCELIST}
  ${MBEDTLS_CONFIG_FILE}
  timing_alt.h
  threading.c)
if(CMSDK_IS_LINK)
  list(APPEND PRIVATE_SOURCELIST ${CMAKE_CURRENT_SOURCE_DIR}/mbedtls/library/net_sockets.c)
else()
  list(APPEND PRIVATE_SOURCELIST ${CMAKE_CURRENT_SOURCE_DIR}/net_sockets.c)
endif()
if(CMSDK_IS_ARM)
  set(LIB_OPTION kernel)
endif()
cmsdk2_add_library(
  NAME mbedtls
  OPTION "${LIB_OPTION}"
  CONFIG release
  ARCH ${CMSDK_ARCH}
  TARGET RELEASE_TARGET)
target_sources(${RELEASE_TARGET}
  PUBLIC
  ${PUBLIC_SOURCES}
  PRIVATE
  ${PRIVATE_SOURCELIST})
target_compile_definitions(${RELEASE_TARGET}
  PUBLIC
  HAVE_LWIP_SOCKETS_H
  PRIVATE
  IS_LOCAL_BUILD=1
  MBEDTLS_CONFIG_FILE=\"${MBEDTLS_CONFIG_FILE}\")
target_include_directories(${RELEASE_TARGET}
  PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
  PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${CMAKE_CURRENT_SOURCE_DIR}/config/mbedtls
  mbedtls/include)
if(CMSDK_IS_ARM)
  target_include_directories(${RELEASE_TARGET}
    PRIVATE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../lwip/include>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../lwip/lwip-${LWIP_VERSION}/src/include>)
endif()
if(CMSDK_IS_WINDOWS)
  target_link_libraries(${RELEASE_TARGET}
    INTERFACE ws2_32 wsock32 setupapi)
endif()
cmsdk2_add_library(
  NAME mbedtls
  OPTION "${LIB_OPTION}"
  CONFIG debug
  ARCH ${CMSDK_ARCH}
  TARGET DEBUG_TARGET)
cmsdk2_copy_target(
  SOURCE ${RELEASE_TARGET}
  DESTINATION ${DEBUG_TARGET})
target_compile_options(${RELEASE_TARGET} PUBLIC -Os)
if(${CMSDK_IS_ARM})
  message("Linking to StratifyOS MCU for header inclusion")
  set(DEPENDENCIES StratifyOS_interface)
endif()

cmsdk2_library_add_dependencies(
  TARGET ${DEBUG_TARGET}
  DEPENDENCIES ${DEPENDENCIES}
  TARGETS DEBUG_TARGET_LIST)
cmsdk2_library_add_dependencies(
  TARGET ${RELEASE_TARGET}
  DEPENDENCIES ${DEPENDENCIES}
  TARGETS RELEASE_TARGET_LIST)

foreach(TARGET ${DEBUG_TARGET_LIST})
  get_target_property(ARCH ${TARGET} CMSDK_PROPERTY_ARCH)
  target_compile_definitions(${TARGET} PUBLIC __${ARCH}=__${ARCH})
endforeach()

foreach(TARGET ${RELEASE_TARGET_LIST})
  get_target_property(ARCH ${TARGET} CMSDK_PROPERTY_ARCH)
  target_compile_definitions(${TARGET} PUBLIC __${ARCH}=__${ARCH})
endforeach()

target_compile_options(${DEBUG_TARGET} PUBLIC -g)
install(FILES ${PROJECT_NAME}.cmake
  DESTINATION ${CMSDK_LOCAL_PATH}/cmake/targets)


