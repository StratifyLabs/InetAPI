

if(NOT DEFINED IS_SDK)
	include(API)
	cmsdk_include_target(mbedtls_kernel "${STRATIFYAPI_CONFIG_LIST}")
endif()
