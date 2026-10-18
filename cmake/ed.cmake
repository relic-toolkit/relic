message(STATUS "Elliptic Edwards curve over prime fields arithmetic configuration (ED module):\n")

message("   ** Options for the prime elliptic Edwards curve module (default = all on):")
message("      ED_PRECO=[off|on] Build precomputation table for generator.")

message("   ** Available prime elliptic Edwards curve methods (default = PROJC;LWNAF;BASIC):")
message("      ED_METHD=BASIC    Affine coordinates.")
message("      ED_METHD=PROJC  	 Simple projective twisted Edwards coordinates.")
message("      ED_METHD=EXTND 	 Extended projective twisted Edwards coordinates.\n")

message("      *** variable-base multiplication method ***")
message("      ED_METHD=BASIC    Binary method.")
message("      ED_METHD=MONTY    Montgomery ladder method.")
message("      ED_METHD=LWNAF    Left-to-right window NAF method.")
message("      ED_METHD=LWREG    Left-to-right regular recoding method.\n")

message("      *** fixed-base multiplication method ***")
message("      ED_METHD=BASIC    Single-table comb method for fixed point multiplication.")
message("      ED_METHD=LWREG    Regular signed comb method for constant-time fixed point multiplication.")
message("      ED_METHD=COMBD    Double-table comb method for fixed point multiplication.\n")

message("      Simultaneous scalar multiplication always interleaves window NAFs.\n")

message("      Note: these methods must be given in order. Ex: ED_METHD=\"EXTND;LWNAF;COMBD\"\n")

option(ED_PRECO "Build precomputation table for generator" on)

# Choose the arithmetic methods.
if (NOT ED_METHD)
	set(ED_METHD "PROJC;LWNAF;BASIC")
endif(NOT ED_METHD)
list(LENGTH ED_METHD ED_LEN)
if (NOT ED_LEN EQUAL 3)
	message(FATAL_ERROR "Incomplete ED_METHD specification: ${ED_METHD}")
endif(NOT ED_LEN EQUAL 3)

list(GET ED_METHD 0 ED_ADD)
list(GET ED_METHD 1 ED_MUL)
list(GET ED_METHD 2 ED_FIX)
if (NOT (ED_FIX STREQUAL "BASIC" OR ED_FIX STREQUAL "LWREG" OR ED_FIX STREQUAL "COMBD"))
	message(FATAL_ERROR "Unsupported fixed point multiplication method in ED_METHD: ${ED_FIX}")
endif()
set(ED_METHD ${ED_METHD} CACHE STRING "Method for prime elliptic Edwards curve arithmetic.")
