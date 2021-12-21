add_executable(single_func_modify_ecx
	single_func_modify_ecx.c
)

add_executable(multi_func_modify_ecx
	multi_func_modify_ecx.c
)

add_executable(c++_single_func_modify_ecx
	c++_single_func_modify_ecx.cpp
)

add_library(test_cycle STATIC static_lib/lib/lib_cycle.c)
add_executable(multi_func_static_lib_modify_ecx
	static_lib/main.c
)
target_link_libraries(multi_func_static_lib_modify_ecx test_cycle)

add_library(test_shared_cycle SHARED shared_lib/lib/lib_cycle.c)
add_executable(multi_func_shared_lib_modify_ecx
	shared_lib/main.c
)
target_link_libraries(multi_func_shared_lib_modify_ecx test_shared_cycle)

add_executable(single_func_modify_bss
	single_func_modify_bss.c
)
