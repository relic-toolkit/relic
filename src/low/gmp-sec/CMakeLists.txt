set(INHERIT "gmp")
if(EXISTS "/usr/include/gmp.h")
   message(STATUS "Found GMP headers.")
endif()

if(EXISTS "/usr/lib/libgmp.dll.a")
   message(STATUS "Found GMP libs.")
endif()