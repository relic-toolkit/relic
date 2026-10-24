message(STATUS "Bilinear pairings arithmetic configuration (PP module):\n")

message("   ** Options for the bilinear pairing module (default = on):\n")

message("      PC_PRECO=[off|on] Build precomputation table for generator of G_2.\n")

message("   ** Available bilinear pairing methods (default = LAZYR;OATEP):\n")

message("      Extension field arithmetic:")
message("      PP_METHD=BASIC    Basic extension field arithmetic.")
message("      PP_METHD=LAZYR    Lazy reduced extension field arithmetic.\n")

message("      Pairing computation:")
message("      PP_METHD=TATEP    Tate pairing.")
message("      PP_METHD=WEILP    Weil pairing.")
message("      PP_METHD=OATEP    Optimal ate pairing.\n")

# Choose the arithmetic methods.
if (NOT PP_METHD)
	set(PP_METHD "LAZYR;OATEP")
endif(NOT PP_METHD)
list(LENGTH PP_METHD PP_LEN)
if (NOT PP_LEN EQUAL 2)
	message(FATAL_ERROR "PP_METHD needs 2 entries: ${PP_METHD}")
endif()

list(GET PP_METHD 0 PP_EXT)
list(GET PP_METHD 1 PP_MAP)
set(PP_METHD ${PP_METHD} CACHE STRING "Method for pairing over prime curves.")

option(PC_PRECO "Build precomputation table for generator of G_2" on)
