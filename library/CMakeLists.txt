set(LIBRARIES FsAPI)
if(${CMSDK_IS_LINK} AND INET_API_IS_MBEDTLS)
  list(APPEND LIBRARIES mbedtls)
endif()
if(${CMSDK_IS_LINK} AND INET_API_HAS_STRATIFY_OS)
  list(APPEND LIBRARIES StratifyOS)
endif()
api2_add_library(
  NAME ${PROJECT_NAME}
  DEPENDENCIES ${LIBRARIES}
  TARGETS TARGET_LIST)

function(add_inet_api_is_mbedtls TARGET)
  if(${INET_API_IS_MBEDTLS})
    set(INET_API_IS_MBEDTLS_VALUE 1)
  else()
    set(INET_API_IS_MBEDTLS_VALUE 0)
  endif()
  target_compile_definitions(${TARGET}
    PUBLIC
    INET_API_IS_MBEDTLS=${INET_API_IS_MBEDTLS_VALUE})
endfunction()

foreach(TARGET ${TARGET_LIST})
  add_inet_api_is_mbedtls(${TARGET})
  if(${CMSDK_IS_LINK})
    if(INET_API_HAS_STRATIFY_OS)
      target_compile_definitions(${TARGET}
        PUBLIC
        INET_API_HAS_STRATIFY_OS=1)
    endif()
  else()
    target_include_directories(${TARGET}
      PUBLIC
      $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../lwip/lwip-${LWIP_VERSION}/src/include>
      $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../lwip/include>
      $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../mbedtls>
      $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../mbedtls/mbedtls/include>
      PRIVATE)
  endif()
endforeach()
