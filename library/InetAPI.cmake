

if(NOT DEFINED API_IS_SDK)
	include(API)
	if(CMSDK_IS_LINK)
		cmsdk_include_target(mbedtls "${API_CONFIG_LIST}")
	endif()

	cmsdk_include_target(InetAPI "${API_CONFIG_LIST}")
endif()
