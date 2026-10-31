# The lower level of prime field arithmetic in a Residue Number System, the
# addition, multiplication and squaring in Fp2, the multiplication and squaring
# in Fp12, and the reduction in Fp2 and Fp3 are vectorized; all else comes from
# the portable backend.
set(INHERIT "easy")
set(ARITH_RNS ON)
set_source_files_properties(${CMAKE_CURRENT_LIST_DIR}/relic_fp_add_low.c
	${CMAKE_CURRENT_LIST_DIR}/relic_fp_mul_low.c
	${CMAKE_CURRENT_LIST_DIR}/relic_fp_rdc_low.c
	${CMAKE_CURRENT_LIST_DIR}/relic_fp_sqr_low.c
	${CMAKE_CURRENT_LIST_DIR}/relic_fpx_add_low.c
	${CMAKE_CURRENT_LIST_DIR}/relic_fpx_mul_low.c
	${CMAKE_CURRENT_LIST_DIR}/relic_fpx_rdc_low.c
	${CMAKE_CURRENT_LIST_DIR}/relic_fpx_sqr_low.c
	PROPERTIES COMPILE_OPTIONS "-mavx512f;-mavx512ifma")
