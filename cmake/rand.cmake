message(STATUS "Available pseudo-random number generators (default = HASHD):\n")

message("   RAND=HASHD     Use the HASH-DRBG generator. (recommended)")
message("   RAND=HMACD     Use the HMAC-DRBG generator.")
message("   RAND=UDEV      Use the operating system underlying generator.")
message("   RAND=CALL      Override the generator with a callback.\n")

message(STATUS "Available random number generator seeders (default = UDEV):\n")

message("   SEED=NONE      Use a zero seed. (horribly insecure!)")
message("   SEED=RDRND     Use Intel RdRand instruction directly.")
message("   SEED=UDEV      Use non-blocking /dev/urandom. (recommended)")
message("   SEED=WCGR      Use Windows' CryptGenRandom. (recommended)\n")

# Choose the pseudo-random number generator.
set(RAND "HASHD" CACHE STRING "Pseudo-random number generator")

# Windows has no /dev/urandom, whatever the compiler.
if(WIN32)

    # Choose the pseudo-random number generator.
    set(SEED "WCGR" CACHE STRING "Random number generator seeder")

else()

    # Choose the pseudo-random number generator.
    set(SEED "UDEV" CACHE STRING "Random number generator seeder")

endif()

if(RAND STREQUAL "RDRND")
	message(FATAL_ERROR "RAND=RDRND was removed, use RAND=HASHD with "
		"SEED=RDRND to seed it from RdRand.")
endif()
if(SEED STREQUAL "")
	message(FATAL_ERROR "SEED is empty, use SEED=NONE for a fixed seed.")
endif()
if(SEED STREQUAL "LIBC")
	message(FATAL_ERROR "SEED=LIBC was removed, use SEED=NONE for a fixed "
		"seed or a real seeder such as UDEV.")
endif()
if(NOT RAND MATCHES "^(HASHD|HMACD|UDEV|CALL)$")
	message(FATAL_ERROR "Unknown generator RAND=${RAND}, choose one of: "
		"HASHD HMACD UDEV CALL")
endif()
if(NOT SEED MATCHES "^(NONE|RDRND|UDEV|WCGR)$")
	message(FATAL_ERROR "Unknown seeder SEED=${SEED}, choose one of: "
		"NONE RDRND UDEV WCGR")
endif()
