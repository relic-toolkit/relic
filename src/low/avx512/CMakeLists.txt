# The lower level of prime field arithmetic in a Residue Number System, the
# addition, multiplication, squaring and reduction in Fp2 and Fp3, the
# multiplication and squaring in Fp8, Fp12, Fp16 and Fp24, and the doubling and
# additions of points on prime curves and on curves over Fp2 are vectorized; all
# else comes from the portable backend.
set(INHERIT "easy")
set(ARITH_RNS ON)
# Every source of the backend uses the vector instructions.
file(GLOB AVX512_SRCS ${CMAKE_CURRENT_LIST_DIR}/*.c)
set_source_files_properties(${AVX512_SRCS}
	PROPERTIES COMPILE_OPTIONS "-mavx512f;-mavx512ifma")
