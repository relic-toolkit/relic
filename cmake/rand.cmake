message(STATUS "Available pseudo-random number generators (default = HASHD):\n")

message("   RAND=HASHD     Use the HASH-DRBG generator. (recommended)")
message("   RAND=RDRND     Use Intel RdRand instruction directly.")
message("   RAND=UDEV      Use the operating system underlying generator.")
message("   RAND=CALL      Override the generator with a callback.\n")

message(STATUS "Available random number generator seeders (default = UDEV):\n")

message("   SEED=ZERO      Use a zero seed. (horribly insecure!)")
message("   SEED=RDRND     Use Intel RdRand instruction directly.")
message("   SEED=UDEV      Use non-blocking /dev/urandom. (recommended)")
message("   SEED=WCGR      Use Windows' CryptGenRandom. (recommended)\n")

# Choose the pseudo-random number generator.
set(RAND "HASHD" CACHE STRING "Pseudo-random number generator")

if(MSVC)

    # Choose the pseudo-random number generator.
    set(SEED "WCGR" CACHE STRING "Random number generator seeder")

else()

    # Choose the pseudo-random number generator.
    set(SEED "UDEV" CACHE STRING "Random number generator seeder")

endif()

if(SEED STREQUAL "")
	message(FATAL_ERROR "SEED is empty, use SEED=ZERO for a fixed seed.")
endif()
if(SEED STREQUAL "LIBC")
	message(FATAL_ERROR "SEED=LIBC was removed, use SEED=ZERO for a fixed "
		"seed or a real seeder such as UDEV.")
endif()
