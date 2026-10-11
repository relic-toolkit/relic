message(STATUS "Elliptic Edwards curve over prime fields arithmetic configuration (ED module):\n")

message("   ** Options for the prime elliptic Edwards curve module (default = all on):")
message("      ED_PRECO=[off|on] Build precomputation table for generator.")
message("      RLC_DEPTH=w        Width w in [2,6] of precomputation table for fixed point methods.")

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
message("      ED_METHD=COMBD    Double-table comb method for fixed point multiplication.\n")

message("      Simultaneous scalar multiplication always interleaves window NAFs.\n")

message("      Note: these methods must be given in order. Ex: ED_METHD=\"EXTND;LWNAF;COMBD\"\n")

option(ED_PRECO "Build precomputation table for generator" on)

# Choose the arithmetic methods.
if (NOT ED_METHD)
	set(ED_METHD "PROJC;LWNAF;BASIC")
endif(NOT ED_METHD)
list(LENGTH ED_METHD ED_LEN)
# Convert the older format, which had a method for simultaneous multiplication.
if (ED_LEN EQUAL 4)
	message(WARNING "ED_METHD no longer selects simultaneous multiplication, ignoring the last entry of ${ED_METHD}")
	list(REMOVE_AT ED_METHD 3)
	set(ED_METHD ${ED_METHD} CACHE STRING "Method for prime elliptic Edwards curve arithmetic." FORCE)
	list(LENGTH ED_METHD ED_LEN)
endif(ED_LEN EQUAL 4)
if (NOT ED_LEN EQUAL 3)
	message(FATAL_ERROR "Incomplete ED_METHD specification: ${ED_METHD}")
endif(NOT ED_LEN EQUAL 3)

list(GET ED_METHD 0 ED_ADD)
list(GET ED_METHD 1 ED_MUL)
list(GET ED_METHD 2 ED_FIX)
# The single-table comb method is now the basic fixed-base method.
if (ED_FIX STREQUAL "COMBS")
	message(WARNING "ED_METHD=COMBS is now called BASIC for fixed point multiplication")
	set(ED_FIX "BASIC")
	list(REMOVE_AT ED_METHD 2)
	list(INSERT ED_METHD 2 "BASIC")
	set(ED_METHD ${ED_METHD} CACHE STRING "Method for prime elliptic Edwards curve arithmetic." FORCE)
endif(ED_FIX STREQUAL "COMBS")
if (NOT (ED_FIX STREQUAL "BASIC" OR ED_FIX STREQUAL "COMBD"))
	message(FATAL_ERROR "Unsupported fixed point multiplication method in ED_METHD: ${ED_FIX}")
endif()
set(ED_METHD ${ED_METHD} CACHE STRING "Method for prime elliptic Edwards curve arithmetic.")
