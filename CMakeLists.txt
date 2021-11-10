project(bin-callgraph)

SET(CAPSTONE_INCLUDE "" CACHE STRING "Optional capstone include path")
SET(CAPSTONE_LIB "" CACHE STRING "Optional capstone library path")

if (NOT ${CAPSTONE_INCLUDE} STREQUAL "")
	include_directories(${CAPSTONE_INCLUDE})
endif()

if (NOT ${CAPSTONE_LIB} STREQUAL "")
	link_directories(${CAPSTONE_LIB})
endif()

add_executable(instr instr.cpp)
target_link_libraries(instr capstone)
