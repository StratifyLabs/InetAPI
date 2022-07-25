
set(LIBRARIES VarAPI FsAPI ChronoAPI)
if(CMSDK_IS_LINK AND INET_API_IS_MBEDTLS)
  list(APPEND LIBRARIES mbedtls)
endif()
if(CMSDK_IS_LINK AND INET_API_HAS_STRATIFY_OS)
  list(APPEND LIBRARIES StratifyOS)
endif()

api_add_api_library(${PROJECT_NAME} "${LIBRARIES}")

function(add_inet_api_is_mbedtls TARGET)
  if(${INET_API_IS_MBEDTLS})
    set(INET_API_IS_MBEDTLS_VALUE 1)
  else()
    set(INET_API_IS_MBEDTLS_VALUE 0)
  endif()
  target_compile_definitions(${TARGET}
    PUBLIC
    INET_API_IS_MBEDTLS=${INET_API_IS_MBEDTLS_VALUE}
    )
endfunction()

if(CMSDK_IS_LINK)

  add_inet_api_is_mbedtls(InetAPI_release_link)
  add_inet_api_is_mbedtls(InetAPI_debug_link)

  if(INET_API_HAS_STRATIFY_OS)
    macro(add_stratify_os CONFIG)
      target_compile_definitions(InetAPI_${CONFIG}_link
        PUBLIC
        INET_API_HAS_STRATIFY_OS=1
        )
    endmacro()

    add_stratify_os(release)
    add_stratify_os(debug)
  endif()

endif()

if(CMSDK_IS_ARM)
  macro(add_lwip_include ARCH)

    add_inet_api_is_mbedtls(InetAPI_release_${ARCH})
    add_inet_api_is_mbedtls(InetAPI_release_${ARCH})

    target_include_directories(InetAPI_debug_${ARCH}
      PUBLIC
      $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../lwip/lwip-${LWIP_VERSION}/src/include>
      $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../lwip/include>
      $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../mbedtls>
      $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../mbedtls/mbedtls/include>
      PRIVATE
      )

    target_include_directories(InetAPI_release_${ARCH}
      PUBLIC
      $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../lwip/lwip-${LWIP_VERSION}/src/include>
      $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../lwip/include>
      $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../mbedtls>
      $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../mbedtls/mbedtls/include>
      PRIVATE
      )
  endmacro()

  add_lwip_include(${CMSDK_ARCH})
  foreach(ARCH ${CMSDK_ARCH_LIST})
    add_lwip_include(${ARCH})
  endforeach()
endif()
