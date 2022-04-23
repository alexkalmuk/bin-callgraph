cmake_minimum_required(VERSION 3.0)
project(bin-callgraph)

SET(ENGINE "" CACHE STRING "Possible options: zydis, capstone (experimental)")
SET(CAPSTONE_INCLUDE "" CACHE STRING "Optional capstone include path")
SET(CAPSTONE_LIB "" CACHE STRING "Optional capstone library path")

include_directories(${PROJECT_SOURCE_DIR})

if ("${ENGINE}" STREQUAL "zydis")
	# Register Zydis dependency.
	# Disable build of tools and examples.
	option(ZYDIS_BUILD_TOOLS "" OFF)
	option(ZYDIS_BUILD_EXAMPLES "" OFF)
	add_subdirectory("deps/zydis")

	add_compile_options(-DUSE_ZYDIS)

	SET(SRC ${SRC} disasm/zydis.cpp)

	SET(LIBS ${LIBS} Zydis)
elseif ("${ENGINE}" STREQUAL "capstone")
	# FIXME Either remove or fix CAPSTONE. Zydis currently
	# shows more promising features like instruction modification.
	message(FATAL_ERROR "CAPSTONE is not used currently")

	if (NOT ${CAPSTONE_INCLUDE} STREQUAL "")
		include_directories(${CAPSTONE_INCLUDE})
	endif()

	if (NOT ${CAPSTONE_LIB} STREQUAL "")
		link_directories(${CAPSTONE_LIB})
	endif()

	add_compile_options(-DUSE_CAPSTONE)

	SET(SRC ${SRC} disasm/capstone.cpp)
	SET(LIBS ${LIBS} capstone)
else()
	message(FATAL_ERROR "Specify -DENGINE:STRING=zydis or -DENGINE:STRING=capstone (experimental)")
endif()

add_executable(instr
	instr.cpp
	${SRC}
)

target_link_libraries(instr
	${LIBS}
)

add_subdirectory(test)
