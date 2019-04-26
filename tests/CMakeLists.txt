cmake_minimum_required (VERSION 2.6)
project (handler_plug)
enable_testing()

# -fdiagnostics-show-line-numbers is enabled by default in gcc-9
# we need to disable it (if the flag exists) to make the tests pass
set(HOST_CFLAGS)
include(CheckCCompilerFlag)
check_c_compiler_flag(-fno-diagnostics-show-line-numbers HAVE_NO_NL)
if(HAVE_NO_NL)
    set(HOST_CFLAGS -fno-diagnostics-show-line-numbers)
endif()

macro(add_test_wrap test_name)
    add_test("${test_name}" bash -o pipefail -c
        "LC_ALL=C CCACHE_DISABLE=1 MALLOC_PERTURB_=170 testdir='${test_name}' HOST_CFLAGS='${HOST_CFLAGS}' sh ./runtest.sh")
endmacro()

if("${CMAKE_CXX_COMPILER}" MATCHES ".*NOTFOUND")
    message(FATAL_ERROR "
Unable to find system C++ compiler!")
endif()

execute_process(COMMAND "${CMAKE_CXX_COMPILER}" "-print-file-name=plugin"
    RESULT_VARIABLE GCC_HOST_STATUS
    OUTPUT_VARIABLE GCC_PLUG_DIR OUTPUT_STRIP_TRAILING_WHITESPACE)
if (NOT "${GCC_HOST_STATUS}" EQUAL 0)
    message(FATAL_ERROR "failed to validate GCC_HOST")
endif()

add_test_wrap(signal_and_wrapper)
add_test_wrap(sigaction_and_staticVar)
add_test_wrap(sig_bash)
add_test_wrap(sigbus_systemd)
add_test_wrap(cswrap)
add_test_wrap(ok_example)
add_test_wrap(changed_errno)
add_test_wrap(restore_and_change)
add_test_wrap(destroy_stored_errno)
add_test_wrap(CFG_loop)
add_test_wrap(own_exit)
add_test_wrap(attribute_cleanup)
