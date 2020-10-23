
set(LIBRARIES VarAPI FsAPI ChronoAPI)
if(SOS_IS_LINK)
	list(APPEND LIBRARIES mbedtls)
endif()

stratifyapi_add_api_library(${PROJECT_NAME} "${LIBRARIES}")
