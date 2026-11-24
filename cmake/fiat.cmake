# Generates Fiat-Crypto code for the prime that test_fp uses. The fiat target
# runs this script with TEST_FP, FIAT_CRYPTO, FIAT_DIR, FIAT_LOW and WSIZE
# defined.

if(NOT FIAT_CRYPTO)
	set(FIAT_CRYPTO "$ENV{FIAT_CRYPTO}")
endif()
set(MONT "${FIAT_CRYPTO}/src/ExtractionOCaml/word_by_word_montgomery")
if(NOT FIAT_CRYPTO OR NOT EXISTS "${MONT}")
	message(FATAL_ERROR "Set FIAT_CRYPTO to the root folder of a built "
		"Fiat-Crypto, as ${MONT} was not found.")
endif()

message(STATUS "Running test_fp to discover prime modulus.")
execute_process(COMMAND "${TEST_FP}" OUTPUT_VARIABLE OUTPUT_CONTENT
	RESULT_VARIABLE RESULT)
if(NOT RESULT EQUAL 0)
	message(FATAL_ERROR "Running ${TEST_FP} failed: ${RESULT}")
endif()
string(REGEX MATCHALL "[(0-9)|(A-F)]+[ \n]" MATCHES "${OUTPUT_CONTENT}")

# The prime is the longest hexadecimal string in the output.
set(LONGEST "0")
set(PRIME "")
foreach(MATCH ${MATCHES})
	STRING(STRIP "${MATCH}" MATCH)
	STRING(LENGTH "${MATCH}" LEN)
	if (${LEN} GREATER ${LONGEST})
		set(LONGEST ${LEN})
		set(PRIME "${MATCH}")
	endif()
endforeach()
if(PRIME STREQUAL "")
	message(FATAL_ERROR "Could not find the prime modulus in the output "
		"of ${TEST_FP}.")
endif()

execute_process(COMMAND "${MONT}" fp ${WSIZE} "0x${PRIME}"
	OUTPUT_VARIABLE OUTPUT_CONTENT RESULT_VARIABLE RESULT)
if(NOT RESULT EQUAL 0 OR OUTPUT_CONTENT STREQUAL "")
	message(FATAL_ERROR "Running ${MONT} failed: ${RESULT}")
endif()
# Keep the generated functions private, unless the generator already did.
string(REGEX REPLACE "(^|\n)void" "\\1static void" OUTPUT_CONTENT
	"${OUTPUT_CONTENT}")

# The sources include fiat_fp.c from their own folder, so they all go there.
file(MAKE_DIRECTORY "${FIAT_DIR}")
file(GLOB TMPLS "${FIAT_LOW}/*.tmpl")
foreach(TMPL ${TMPLS})
	get_filename_component(SRC "${TMPL}" NAME_WE)
	configure_file("${TMPL}" "${FIAT_DIR}/${SRC}.c" COPYONLY)
endforeach()
# Written last, as its presence tells CMake that the code is complete.
file(WRITE "${FIAT_DIR}/fiat_fp.c" "${OUTPUT_CONTENT}")
message(STATUS "Generated ${FIAT_DIR}, run CMake again to build with it.")
