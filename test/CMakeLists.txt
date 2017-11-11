file(GLOB TEST_SUPPORT *.sh)
add_custom_target(install_test_harness ALL
	ln -f ${TEST_SUPPORT} .
	SOURCES ${TEST_SUPPORT}
)

add_executable(block_port block_port.c)
target_include_directories(block_port PRIVATE ../include)
target_link_libraries(block_port nsocker)

add_test(preload preload.sh)
add_test(preload-error preload-error.sh)
