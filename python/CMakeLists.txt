find_program (PY2 python2)
find_program (PY3 python3)

option(BUILD_PY2 "Build python2 extension" ${PY2_FOUND})
option(BUILD_PY3 "Build python3 extension" ${PY3_FOUND})
configure_file("setup.py.in" "setup.py")
SET(DEPS nsocker.c)

function(build_python python)
	set(OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/build/timestamp-${python}")
	add_custom_command(
		OUTPUT ${OUTPUT}
		COMMAND ln -s ${CMAKE_CURRENT_SOURCE_DIR}/nsocker.c . || true
		COMMAND ${python} setup.py build
		COMMAND ${CMAKE_COMMAND} -E touch ${OUTPUT}
		DEPENDS ${DEPS})
	add_custom_target(${python} ALL DEPENDS ${OUTPUT} SOURCES ${DEPS})
	# Do not use --prefix, the python prefix must be used
	install(CODE "execute_process(COMMAND
		sh ${CMAKE_CURRENT_SOURCE_DIR}/install-helper.sh
		${CMAKE_CURRENT_BINARY_DIR}
		${python} setup.py install)")
endfunction(build_python)

if (BUILD_PY2)
	build_python(python2)
endif(BUILD_PY2)

if (BUILD_PY3)
	build_python(python3)
endif(BUILD_PY3)
