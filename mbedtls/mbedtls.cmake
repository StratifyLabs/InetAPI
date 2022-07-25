

if(NOT DEFINED API_IS_SDK)
	include(API)
	cmsdk_include_target(mbedtls_kernel "${API_CONFIG_LIST}")
endif()
