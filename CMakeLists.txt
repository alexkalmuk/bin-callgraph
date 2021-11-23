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
#add_compile_options(-DUSE_CAPSTONE)

# Register Zydis dependency.
# Disable build of tools and examples.
option(ZYDIS_BUILD_TOOLS "" OFF)
option(ZYDIS_BUILD_EXAMPLES "" OFF)
add_subdirectory("deps/zydis")

add_compile_options(-DUSE_ZYDIS)

add_executable(instr
	instr.cpp
	disasm/capstone.cpp
	disasm/zydis.cpp
)
target_link_libraries(instr capstone Zydis)

add_subdirectory(test)
