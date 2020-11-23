
set(DEPENDENCIES TestAPI FsAPI InetAPI ThreadAPI)


api_add_test_executable(${PROJECT_NAME} 32768 "${DEPENDENCIES}")



