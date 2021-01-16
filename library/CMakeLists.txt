
set(LIBRARIES VarAPI FsAPI ChronoAPI)
if(SOS_IS_LINK)
	list(APPEND LIBRARIES mbedtls)
endif()

api_add_api_library(${PROJECT_NAME} "${LIBRARIES}")

if(SOS_IS_ARM)
	macro(add_lwip_include ARCH)
		target_include_directories(InetAPI_debug_${ARCH}
			PUBLIC
			$<INSTALL_INTERFACE:include/lwip>
			$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../lwip/lwip-2.1.2/src/include>
			$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../lwip/include>
			PRIVATE
			)

		target_include_directories(InetAPI_release_${ARCH}
			PUBLIC
			$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../lwip/lwip-2.1.2/src/include>
			$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../lwip/include>
			PRIVATE
			)
	endmacro()

	add_lwip_include(${SOS_ARCH})
	foreach(ARCH ${SOS_ARCH_LIST})
		add_lwip_include(${ARCH})
	endforeach()
endif()
