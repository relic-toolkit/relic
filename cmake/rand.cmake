message(STATUS "Available pseudo-random number generators (default = HASH):\n")

message("   RAND=HASH      Use the HASH-DRBG generator. (recommended)")
message("   RAND=UDEV      Use the operating system underlying generator.")
message("   RAND=FIPS      Use the FIPS 186-2 (CN1) SHA1-based generator.")
message("   RAND=CALL      Override the generator with a callback.\n")

message(STATUS "Available random number generator seeders (default = UDEV):\n")

message("   SEED=          Use a zero seed. (horribly insecure!)")
message("   SEED=LIBC      Use rand()/random() functions. (insecure!)")
message("   SEED=WCGR      Use Windows' CryptGenRandom. (recommended)")
message("   SEED=UDEV      Use non-blocking /dev/urandom. (recommended)")
message("   SEED=DEV       Use blocking /dev/random. (recommended)")
message("   SEED=RDRND     Use Intel RdRand instruction.\n")

# Choose the pseudo-random number generator.
set(RAND "HASH" CACHE STRING "Pseudo-random number generator")

# Choose the pseudo-random number generator.
set(SEED "UDEV" CACHE STRING "Random number generator seeder")
