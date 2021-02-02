
set(LIBRARIES VarAPI FsAPI ChronoAPI)
if(SOS_IS_LINK)
	list(APPEND LIBRARIES mbedtls)
endif()

api_add_api_library(${PROJECT_NAME} "${LIBRARIES}")

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
