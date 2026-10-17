set(INHERIT "gmp-sec")
include(../cmake/gmp.cmake)
if(GMP_FOUND)
	include_directories(${GMP_INCLUDE_DIR})
	set(ARITH_LIBS ${GMP_LIBRARIES})
endif(GMP_FOUND)

# The generated code depends on the prime that test_fp uses, so the first build
# takes the GMP backend, "make fiat" writes the code to the build tree, and the
# next run of CMake builds with it. Nothing is written to the source tree.
set(FIAT_DIR "${PROJECT_BINARY_DIR}/fiat")
set(ARITH_SOURCE_DIR "${FIAT_DIR}")
set(FIAT_CRYPTO "$ENV{FIAT_CRYPTO}" CACHE PATH "Root folder of Fiat-Crypto")

if(EXISTS "${FIAT_DIR}/fiat_fp.c")
	message(STATUS "Configured Fiat-Crypto: using the code in ${FIAT_DIR}, "
		"which must be removed to generate it again.")
else()
	message(STATUS "Configured Fiat-Crypto: set FIAT_CRYPTO to its root "
		"folder, run make fiat, then run CMake again and build. The code "
		"needs Montgomery reduction (MONTY in FP_METHD).")
endif()

if(TESTS GREATER 0)
	add_custom_target(fiat
		COMMAND ${CMAKE_COMMAND} "-DTEST_FP=$<TARGET_FILE:test_fp>"
			"-DFIAT_CRYPTO=${FIAT_CRYPTO}" "-DFIAT_DIR=${FIAT_DIR}"
			"-DFIAT_LOW=${CMAKE_CURRENT_LIST_DIR}" "-DWSIZE=${WSIZE}"
			-P "${PROJECT_SOURCE_DIR}/cmake/fiat.cmake"
		COMMENT "Generating Fiat-Crypto code for the prime of test_fp"
		VERBATIM)
	add_dependencies(fiat test_fp)
else()
	message(WARNING "ARITH=fiat needs TESTS > 0, since test_fp tells the "
		"prime to generate code for.")
endif()
