message(STATUS "Binary elliptic curve arithmetic configuration (EB module):\n")

message("   ** Options for the binary elliptic curve module (default = on, w = 4):\n")

message("      EB_PRECO=[off|on] Build precomputation table for generator.")

message("   ** Available binary elliptic curve methods (default = PROJC;LWNAF;BASIC):\n")

message("      Point representation:")
message("      EB_METHD=BASIC    Affine coordinates.")
message("      EB_METHD=PROJC    Projective coordinates (L�pez-Dahab for ordinary curves).\n")

message("      Variable-base scalar multiplication:")
message("      EB_METHD=BASIC    Binary double-and-add method.")
message("      EB_METHD=LODAH    Lopez-Dahab constant-time point multiplication.")
message("      EB_METHD=LWNAF    Left-to-right window (T)NAF method.")
message("      EB_METHD=RWNAF    Right-to-left window (T)NAF method.")
message("      EB_METHD=HALVE    Halving method.\n")

message("      Fixed-base scalar multiplication:")
message("      EB_METHD=BASIC    Single-table comb method for fixed point multiplication.")
message("      EB_METHD=LWREG    Regular signed comb method for constant-time fixed point multiplication.")
message("      EB_METHD=COMBD    Double-table comb method for fixed point multiplication.")
message("      EB_METHD=LWNAF    Left-to-right window (T)NAF method.\n")

message("      Simultaneous scalar multiplication always interleaves window (T)NAFs.\n")

option(EB_PRECO "Build precomputation table for generator" on)

# Choose the arithmetic methods.
if (NOT EB_METHD)
	set(EB_METHD "PROJC;LWNAF;BASIC")
endif(NOT EB_METHD)
list(LENGTH EB_METHD EB_LEN)
# Convert the older format, which had a method for simultaneous multiplication.
if (EB_LEN EQUAL 4)
	message(WARNING "EB_METHD no longer selects simultaneous multiplication, ignoring the fourth entry of ${EB_METHD}")
	list(REMOVE_AT EB_METHD 3)
	set(EB_METHD ${EB_METHD} CACHE STRING "Method for binary elliptic curve arithmetic." FORCE)
	list(LENGTH EB_METHD EB_LEN)
endif(EB_LEN EQUAL 4)
if (NOT EB_LEN EQUAL 3)
	message(FATAL_ERROR "Incomplete EB_METHD specification: ${EB_METHD}")
endif(NOT EB_LEN EQUAL 3)

list(GET EB_METHD 0 EB_ADD)
list(GET EB_METHD 1 EB_MUL)
list(GET EB_METHD 2 EB_FIX)
# The single-table comb method is now the basic fixed-base method.
if (EB_FIX STREQUAL "COMBS")
	message(WARNING "EB_METHD=COMBS is now called BASIC for fixed point multiplication")
	set(EB_FIX "BASIC")
	list(REMOVE_AT EB_METHD 2)
	list(INSERT EB_METHD 2 "BASIC")
	set(EB_METHD ${EB_METHD} CACHE STRING "Method for binary elliptic curve arithmetic." FORCE)
endif(EB_FIX STREQUAL "COMBS")
if (NOT (EB_FIX STREQUAL "BASIC" OR EB_FIX STREQUAL "LWREG" OR EB_FIX STREQUAL "COMBD" OR EB_FIX STREQUAL "LWNAF"))
	message(FATAL_ERROR "Unsupported fixed point multiplication method in EB_METHD: ${EB_FIX}")
endif()
set(EB_METHD ${EB_METHD} CACHE STRING "Method for binary elliptic curve arithmetic.")
