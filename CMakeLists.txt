cmake_minimum_required(VERSION 2.8)
project(nsocker)
include(GNUInstallDirs)
include(FindPkgConfig)
add_subdirectory(python)

pkg_check_modules (EV REQUIRED libevent_core)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -Wno-unused-parameter")

add_executable(nsocker-daemon daemon.c fd.c)
target_include_directories(nsocker-daemon PRIVATE include ${EV_INCLUDE_DIRS})
target_link_libraries(nsocker-daemon ${EV_LIBRARIES})

add_library(nsocker SHARED client.c tls.c fd.c)
target_include_directories(nsocker PRIVATE include)
target_link_libraries(nsocker pthread)

add_library(nsocker-preload SHARED preload.c)
target_include_directories(nsocker-preload PRIVATE include)
target_link_libraries(nsocker-preload dl nsocker)
install(TARGETS nsocker nsocker-preload nsocker-daemon
	RUNTIME DESTINATION bin
	LIBRARY DESTINATION lib)

file(GLOB HEADERS include/nsocker/*.h *.h)
add_custom_target(headers SOURCES ${HEADERS})

install(DIRECTORY include DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
