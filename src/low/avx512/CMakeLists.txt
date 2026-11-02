# The lower level of prime field arithmetic in a Residue Number System, the
# addition, multiplication and squaring in Fp2, the multiplication and squaring
# in Fp12, the reduction in Fp2 and Fp3, and the doubling and additions of
# points on prime curves are vectorized; all else comes from the portable
# backend.
set(INHERIT "easy")
set(ARITH_RNS ON)
# Every source of the backend uses the vector instructions.
file(GLOB AVX512_SRCS ${CMAKE_CURRENT_LIST_DIR}/*.c)
set_source_files_properties(${AVX512_SRCS}
	PROPERTIES COMPILE_OPTIONS "-mavx512f;-mavx512ifma")
