cmake_minimum_required(VERSION 3.0)
project(bin-callgraph)

SET(CAPSTONE_INCLUDE "" CACHE STRING "Optional capstone include path")
SET(CAPSTONE_LIB "" CACHE STRING "Optional capstone library path")

include_directories(${PROJECT_SOURCE_DIR})

if (NOT ${CAPSTONE_INCLUDE} STREQUAL "")
	include_directories(${CAPSTONE_INCLUDE})
endif()

if (NOT ${CAPSTONE_LIB} STREQUAL "")
	link_directories(${CAPSTONE_LIB})
endif()

add_executable(instr
	instr.cpp
	disasm/capstone.cpp
)
target_link_libraries(instr capstone)
