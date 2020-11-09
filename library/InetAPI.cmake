

if(NOT DEFINED IS_SDK)
	include(API)
	if(SOS_IS_LINK)
		sos_sdk_include_target(mbedtls "${STRATIFYAPI_CONFIG_LIST}")
	endif()

	sos_sdk_include_target(InetAPI "${STRATIFYAPI_CONFIG_LIST}")
endif()
