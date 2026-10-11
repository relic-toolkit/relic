message(STATUS "Prime elliptic curve arithmetic configuration (EP module):\n")

message("   ** Options for the prime elliptic curve module (default = all on):\n")

message("      EP_PRECO=[off|on] Build precomputation table for generator.")
message("      RLC_DEPTH=w        Width w in [2,8] of precomputation table for fixed point methods.")

message("   ** Available prime elliptic curve methods (default = PROJC;LWNAF;BASIC;SSWUM):\n")

message("      Point representation:")
message("      EP_METHD=BASIC    Affine coordinates.")
message("      EP_METHD=PROJC    Homogeneous projective coordinates (complete formula).")
message("      EP_METHD=JACOB    Jacobian projective coordinates.\n")

message("      Variable-base scalar multiplication:")
message("      EP_METHD=BASIC    Binary double-and-add method.")
message("      EP_METHD=MONTY    Montgomery ladder method.")
message("      EP_METHD=LWNAF    Left-to-right window NAF method.")
message("      EP_METHD=LWREG    Left-to-right regular recoding method (GLV for curves with endomorphisms).\n")

message("      Fixed-base scalar multiplication:")
message("      EP_METHD=BASIC    Single-table comb method for fixed point multiplication.")
message("      EP_METHD=LWREG    Regular signed comb method for constant-time fixed point multiplication.")
message("      EP_METHD=COMBD    Double-table comb method for fixed point multiplication.\n")

message("      Hash to point on the elliptic curve:")
message("      EP_METHD=BASIC    Hash to x-coordinate and increment.")
message("      EP_METHD=SSWUM    Simplified Shallue-van de Woestijne-Ulas method.")
message("      EP_METHD=SWIFT    SwiftEC hashing method.\n")

message("      Simultaneous scalar multiplication always interleaves window NAFs.\n")

option(EP_PRECO "Build precomputation table for generator" on)

# Choose the arithmetic methods.
if (NOT EP_METHD)
	set(EP_METHD "PROJC;LWNAF;BASIC;SSWUM")
endif(NOT EP_METHD)
list(LENGTH EP_METHD EP_LEN)
# Convert the older format, which had a method for simultaneous multiplication.
if (EP_LEN EQUAL 5)
	message(WARNING "EP_METHD no longer selects simultaneous multiplication, ignoring the fourth entry of ${EP_METHD}")
	list(REMOVE_AT EP_METHD 3)
	set(EP_METHD ${EP_METHD} CACHE STRING "Method for prime elliptic curve arithmetic." FORCE)
	list(LENGTH EP_METHD EP_LEN)
endif(EP_LEN EQUAL 5)
if (NOT EP_LEN EQUAL 4)
	message(FATAL_ERROR "Incomplete EP_METHD specification: ${EP_METHD}")
endif(NOT EP_LEN EQUAL 4)

list(GET EP_METHD 0 EP_ADD)
list(GET EP_METHD 1 EP_MUL)
list(GET EP_METHD 2 EP_FIX)
list(GET EP_METHD 3 EP_MAP)
# The single-table comb method is now the basic fixed-base method.
if (EP_FIX STREQUAL "COMBS")
	message(WARNING "EP_METHD=COMBS is now called BASIC for fixed point multiplication")
	set(EP_FIX "BASIC")
	list(REMOVE_AT EP_METHD 2)
	list(INSERT EP_METHD 2 "BASIC")
	set(EP_METHD ${EP_METHD} CACHE STRING "Method for prime elliptic curve arithmetic." FORCE)
endif(EP_FIX STREQUAL "COMBS")
if (NOT (EP_FIX STREQUAL "BASIC" OR EP_FIX STREQUAL "LWREG" OR EP_FIX STREQUAL "COMBD"))
	message(FATAL_ERROR "Unsupported fixed point multiplication method in EP_METHD: ${EP_FIX}")
endif()
set(EP_METHD ${EP_METHD} CACHE STRING "Method for prime elliptic curve arithmetic.")
