
set(LIBRARIES VarAPI FsAPI ChronoAPI)
if(SOS_IS_LINK AND INET_API_IS_MBEDTLS)
  list(APPEND LIBRARIES mbedtls)
endif()
if(SOS_IS_LINK AND INET_API_HAS_STRATIFY_OS)
  list(APPEND LIBRARIES StratifyOS)
endif()

api_add_api_library(${PROJECT_NAME} "${LIBRARIES}")

if(SOS_IS_LINK AND INET_API_HAS_STRATIFY_OS)
  macro(add_stratify_os CONFIG)
    target_compile_definitions(InetAPI_${CONFIG}_link
      PUBLIC
      INET_API_HAS_STRATIFY_OS=1
      )
  endmacro()

  add_stratify_os(release)
  add_stratify_os(debug)

endif()

if(SOS_IS_ARM)
  macro(add_lwip_include ARCH)
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

  add_lwip_include(${SOS_ARCH})
  foreach(ARCH ${SOS_ARCH_LIST})
    add_lwip_include(${ARCH})
  endforeach()
endif()
