set(INHERIT "gmp-sec")
include(../cmake/gmp.cmake)
if(GMP_FOUND)
	include_directories(${GMP_INCLUDE_DIR})
	set(ARITH_LIBS ${GMP_LIBRARIES})
endif(GMP_FOUND)

set(FIAT_CMAKE ${CMAKE_SOURCE_DIR}/cmake/fiat.cmake)
set(FIAT_FP "${CMAKE_SOURCE_DIR}/../../src/low/fiat-crypto/fiat_fp.c")

add_custom_command(OUTPUT ${FIAT_FP}
	COMMAND ${CMAKE_COMMAND} -P ${FIAT_CMAKE}
	WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}"
	COMMENT "Running test_fp to discover prime modulus."
)

add_custom_target(fiat DEPENDS ${FIAT_FP})
