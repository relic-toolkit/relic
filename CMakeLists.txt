cmake_minimum_required(VERSION 3.10)

project(RELIC C)
set(PROJECT_VERSION_MAJOR "0")
set(PROJECT_VERSION_MINOR "7")
set(PROJECT_VERSION_PATCH "0")
set(PROJECT_VERSION "${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR}.${PROJECT_VERSION_PATCH}")
set(VERSION ${PROJECT_VERSION})

set(INCLUDE ${CMAKE_CURRENT_BINARY_DIR}/include ${CMAKE_CURRENT_SOURCE_DIR}/include ${CMAKE_CURRENT_SOURCE_DIR}/include/low ${CMAKE_CURRENT_SOURCE_DIR}/src/tmpl)
include_directories(${INCLUDE})

set(LIBRARY_OUTPUT_PATH ${PROJECT_BINARY_DIR}/lib)
set(EXECUTABLE_OUTPUT_PATH ${PROJECT_BINARY_DIR}/bin)

set(WFLAGS "-Wall")

message("\n-- Configuring ${PROJECT_NAME} ${PROJECT_VERSION}...\n")

message(STATUS "Available switches (default = CHECK, VERBS, DOCUM, COLOR, SHLIB, STLIB):\n")

message("   DEBUG=[off|on] Build with debugging support.")
message("   CHECK=[off|on] Build with error-checking support.")
message("   VERBS=[off|on] Build with detailed error messages.")
message("   DOCUM=[off|on] Build documentation.")
message("   STRIP=[off|on] Remove unused code and tables of unused algorithms.")
message("   QUIET=[off|on] Build with printing disabled.")
message("   COLOR=[off|on] Build with colored output.")
message("   SHLIB=[off|on] Build shared library.")
message("   STLIB=[off|on] Build static library.")
message("   STBIN=[off|on] Build static binaries.")
message("   AMALG=[off|on] Build amalgamation for better performance.")
message("   AUSAN=[off|on] Build with ASan and UBSan (gcc/clang only).\n")

option(DEBUG "Build with debugging support" off)
option(CHECK "Build with error-checking support" on)
option(VERBS "Build with detailed error messages" on)
option(DOCUM "Build documentation" on)
option(STRIP "Remove unused code and tables of unselected algorithms" off)
option(QUIET "Build with printing disabled" off)
option(COLOR "Build with colored output" on)
option(SHLIB "Build shared library" on)
option(STLIB "Build static library" on)
option(STBIN "Build static binaries" off)
option(AMALG "Build amalgamation" off)
option(AUSAN "Build with ASan and UBSan (gcc/clang only)" off)

message(STATUS "Number of times each test or benchmark is run (default = 100, 100):\n")

message("   TESTS=n        If n > 0, build automated tests and run them n times.")
message("   BENCH=n        If n > 0, build automated benchmarks and run them n * n times.\n")

message(STATUS "Number of available processor cores (default = 1):\n")

message("   CORES=n        If n > 1, enable multithreading support.\n")

message(STATUS "Available modules (default = ALL)\n")

message("   WITH=BN       Multiple precision arithmetic.")
message("   WITH=DV       Temporary double-precision digit vectors.")
message("   WITH=FP       Prime field arithmetic.")
message("   WITH=FPX      Prime extension field arithmetic.")
message("   WITH=FB       Binary field arithmetic.")
message("   WITH=FBX      Binary extension field arithmetic.")
message("   WITH=EP       Elliptic curves over prime fields.")
message("   WITH=EPX      Elliptic curves over extensions of prime fields.")
message("   WITH=EB       Elliptic curves over binary fields.")
message("   WITH=ED       Elliptic Edwards curves over prime fields.")
message("   WITH=EC       Elliptic curve cryptography.")
message("   WITH=PP       Pairings over prime elliptic curves.")
message("   WITH=PC       Pairing-based cryptography.")
message("   WITH=BC       Block ciphers (symmetric encryption).")
message("   WITH=MD       Message digests (hash functions).")
message("   WITH=CP       Cryptographic protocols.")
message("   WITH=MPC      Multi-party computation primitives.")
message("   WITH=ALL      All of the above.")
message("   Note: the programmer is responsible for not using unselected modules.\n")

message(STATUS "Available arithmetic backends (default = easy):\n")

message("   ARITH=easy     Easy-to-understand and portable, but slow backend.")
message("   ARITH=fiat     Backend based on code generated from Fiat-Crypto.")
message("   ARITH=gmp      Backend based on GNU Multiple Precision library.")
message("   ARITH=gmp-sec  Same as above, but using constant-time code.\n")

message(STATUS "Available memory-allocation policies (default = AUTO):\n")

message("   ALLOC=AUTO     All memory is automatically allocated.")
message("   ALLOC=DYNAMIC  All memory is allocated dynamically on demand.\n")

message(STATUS "Supported operating systems (default = LINUX):\n")

message("   OPSYS=         Undefined/No specific operating system.")
message("   OPSYS=LINUX    GNU/Linux operating system.")
message("   OPSYS=FREEBSD  FreeBSD operating system.")
message("   OPSYS=NETBSD   NetBSD operating system.")
message("   OPSYS=MACOSX   Mac OS X operating system.")
message("   OPSYS=WINDOWS  Windows operating system.")
message("   OPSYS=DROID    Android operating system.")
message("   OPSYS=DUINO    Arduino platform.\n")

message(STATUS "Supported multithreading APIs (default = UNDEF):\n")

message("   MULTI=         No multithreading support.")
message("   MULTI=OPENMP   Open Multi-Processing.")
message("   MULTI=PTHREAD  POSIX threads.\n")

message(STATUS "Supported timers (default = HREAL):\n")

message("   TIMER=         No timer.")
message("   TIMER=HREAL    POSIX monotonic high-resolution timer.")
message("   TIMER=HPROC    POSIX per-process high-resolution timer.")
message("   TIMER=HTHRD    POSIX per-thread high-resolution timer.")
message("   TIMER=ANSI     ANSI-compatible timer.")
message("   TIMER=CYCLE    Cycle-counting timer. (architecture-dependant)")
message("   TIMER=PERF     GNU/Linux performance monitoring framework.\n")

message(STATUS "Prefix to identify this build of the library (default = \"\"):\n")

message("   LABEL=relic\n")

message(STATUS "Widths of precomputation tables (default = 5, 4):\n")

message("   RLC_DEPTH=w    Width w in [2,8] of table for fixed exponentiation.")
message("   RLC_WIDTH=w    Width w in [2,6] of table for exponentiation.\n")

# Table sizes for exponentiation methods
set(RLC_DEPTH "5" CACHE STRING "Width of precomputation table for fixed base exponentiation methods.")
set(RLC_WIDTH "4" CACHE STRING "Width of window processing for general exponentiation methods.")

include(cmake/arch.cmake)
include(cmake/err.cmake)
include(cmake/bn.cmake)
include(cmake/fp.cmake)
include(cmake/fpx.cmake)
include(cmake/fb.cmake)
include(cmake/ep.cmake)
include(cmake/eb.cmake)
include(cmake/ed.cmake)
include(cmake/ec.cmake)
include(cmake/pp.cmake)
include(cmake/md.cmake)
include(cmake/rand.cmake)
include(cmake/with.cmake)

# Number of tests and benchmarks
set(BENCH "100" CACHE STRING "Number of times each benchmark is ran.")
set(TESTS "100" CACHE STRING "Number of times each test is ran.")

# Number of cores.
set(CORES "1" CACHE STRING "Number of processor cores available to the library.")

if(NOT CORES STREQUAL "1" AND NOT MULTI)
	set(MULTI OPENMP)
endif()

# Choose the arithmetic backend, which must be one of the folders of src/low.
set(ARITH "easy" CACHE STRING "Arithmetic backend")
string(TOLOWER "${ARITH}" ARITH_DIR)
if(NOT IS_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/src/low/${ARITH_DIR}")
	file(GLOB BACKENDS RELATIVE "${CMAKE_CURRENT_SOURCE_DIR}/src/low"
		"${CMAKE_CURRENT_SOURCE_DIR}/src/low/*")
	string(REPLACE ";" " " BACKENDS "${BACKENDS}")
	message(FATAL_ERROR "Unknown arithmetic backend ARITH=${ARITH}, choose "
		"one of: ${BACKENDS}")
endif()

# Choose the memory-allocation policy.
set(ALLOC "AUTO" CACHE STRING "Allocation policy")

# Simulator of the target platform.
set(SIMUL "$ENV{SIMUL}" CACHE STRING "Path to call a simulator of the target platform.")
set(SIMAR "$ENV{SIMAR}" CACHE STRING "Arguments to call a simulator of the target platform.")
string(REPLACE " " ";" SIMAR "${SIMAR}")

# Linker flags.
string(TOLOWER ${ARITH} LFLAGS)
set(LFLAGS "-L${CMAKE_CURRENT_SOURCE_DIR}/src/low/${LFLAGS}/")
set(LFLAGS "${LFLAGS} $ENV{LDFLAGS} ${LDFLAGS}")

if(STBIN)
	set(LFLAGS "${LFLAGS} -static")
	set(CMAKE_LINK_SEARCH_START_STATIC ON)
	set(CMAKE_LINK_SEARCH_END_STATIC ON)
endif()

# Discover the operating system.
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
	set(OPSYS "LINUX" CACHE STRING "Operating system")
else()
	if(CMAKE_SYSTEM_NAME STREQUAL "FreeBSD")
		set(OPSYS "FREEBSD" CACHE STRING "Operating system")
	else()
		if(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
			set(OPSYS "MACOSX" CACHE STRING "Operating system")
		else()
			if(CMAKE_SYSTEM_NAME STREQUAL "NetBSD")
				set(OPSYS "NETBSD" CACHE STRING "Operating system")
			else()
				if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
					set(OPSYS "WINDOWS" CACHE STRING "Operating system")
				endif()
			endif()
		endif()
	endif()
endif()
if(OPSYS STREQUAL "LINUX")
	add_definitions(-D_GNU_SOURCE)
endif()
message(STATUS "Configured operating system: ${OPSYS}")

if(OPSYS MATCHES "^(LINUX|MACOSX|FREEBSD|NETBSD|DROID)$")
	set(TIMER "HREAL" CACHE STRING "Timer")
else()
	set(TIMER "ANSI" CACHE STRING "Timer")
endif()

if(MSVC)
	#defaults to the DLL runtime library.
	set(RUNTIME "MD" CACHE STRING "MSVC runtime libraries")
	message(STATUS "Supported MSVC runtime libraries (default = MD):\n")
	message("   RUNTIME=MD     DLL runtime library (/MD,/MDd).")
	message("   RUNTIME=MT     Static runtime library (/MT,/MTd).\n")

	#loop over the compile flags to swap /MD and /MT.
	set(CompilerFlags
		CMAKE_C_FLAGS_DEBUG
		CMAKE_C_FLAGS_RELEASE
		CMAKE_C_FLAGS_RELWITHDEBINFO
		CMAKE_C_FLAGS_MINSIZEREL)
	foreach(CompilerFlag ${CompilerFlags})
		if(RUNTIME STREQUAL "MT")
			string(REPLACE "/MD" "/MT" ${CompilerFlag} "${${CompilerFlag}}")
		else()
			string(REPLACE "/MT" "/MD" ${CompilerFlag} "${${CompilerFlag}}")
		endif()
	endforeach()
endif()

# Compiler flags come from CFLAGS on the command line or in the environment.
# When it is empty, the defaults below apply. They are not cached, so that
# switching DEBUG in an existing build directory takes effect.
set(CFLAGS "$ENV{CFLAGS}" CACHE STRING
	"Compiler flags, empty for the defaults.")
if(CFLAGS STREQUAL "")
	if(DEBUG)
		if(MSVC)
			set(CFLAGS "/Od")
		else()
			# Turn off all optimizations.
			set(CFLAGS "-pipe -std=c99 -O0 -fno-omit-frame-pointer")
		endif()
	else()
		if(MSVC)
			set(CFLAGS "/O2")
		else()
			set(CFLAGS "-pipe -std=c99 -O2 -funroll-loops -fomit-frame-pointer")
		endif()
	endif()
endif()
# Turn on debugging symbols.
if(DEBUG)
	if(MSVC)
		set(DFLAGS "/Z7")
	else()
		set(DFLAGS "-ggdb")
	endif()
endif()

# Remove annoying flags when compiler cannot compute buffer sizes.
if (CMAKE_C_COMPILER_ID STREQUAL "GNU")
	set(CFLAGS "${CFLAGS} -Wno-stringop-overflow -Wno-stringop-overread")
endif()

if(AUSAN)
	set(DFLAGS "${DFLAGS} -ggdb -fsanitize=address -fsanitize=undefined")
endif()

# Find OpenMP
if(MULTI STREQUAL "OPENMP")
	if (MSVC)
		set(CFLAGS "${CFLAGS} /openmp")
	else()
		if (OPSYS STREQUAL "MACOSX" AND CMAKE_C_COMPILER_ID MATCHES "Clang")
			# Apple Clang has no OpenMP runtime, so take libomp from Homebrew,
			# which keeps it apart under opt/libomp, or from MacPorts.
			set(OMP_PATHS /opt/homebrew/opt/libomp /usr/local/opt/libomp
				/opt/local /opt/homebrew /usr/local)
			find_path(OMP_INCLUDE_DIR omp.h HINTS ${LIBOMP_ROOT} ENV LIBOMP_ROOT
				PATHS ${OMP_PATHS} PATH_SUFFIXES include include/libomp)
			find_library(OMP_LIBRARY omp HINTS ${LIBOMP_ROOT} ENV LIBOMP_ROOT
				PATHS ${OMP_PATHS} PATH_SUFFIXES lib lib/libomp)
			if(NOT OMP_INCLUDE_DIR OR NOT OMP_LIBRARY)
				message(FATAL_ERROR "MULTI=OPENMP with Apple Clang needs libomp, "
					"from brew install libomp, or LIBOMP_ROOT pointing to it.")
			endif()
			include_directories(${OMP_INCLUDE_DIR})
			set(OpenMP_C "${CMAKE_C_COMPILER}")
			set(OpenMP_C_FLAGS "-Xclang -fopenmp -I${OMP_INCLUDE_DIR}")
			set(OpenMP_C_LIB_NAMES "omp")
			set(OpenMP_omp_LIBRARY "${OMP_LIBRARY}")
			set(CFLAGS "${CFLAGS} -Xclang -fopenmp")
		else()
			set(CFLAGS "${CFLAGS} -fopenmp")
		endif()
		find_package(OpenMP REQUIRED)
	endif()
	set(MULTI "OPENMP" CACHE STRING "Multithreading interface")
else()
	if(MULTI STREQUAL "PTHREAD")
		find_package(Threads REQUIRED)
		set(CFLAGS "${CFLAGS} -pthread")
		set(MULTI "PTHREAD" CACHE STRING "Multithreading interface")
	endif()
endif()

if(ARITH STREQUAL "gmp" OR ARITH STREQUAL "gmp-sec")
	include(cmake/gmp.cmake)
	if(GMP_FOUND)
		include_directories(${GMP_INCLUDE_DIR})
		set(ARITH_LIBS ${GMP_LIBRARIES})
	endif()
endif()

# Let the linker remove unused code and data when stripping.
if(STRIP)
	if(MSVC)
		set(CFLAGS "${CFLAGS} /Gy /Gw")
		set(LFLAGS "${LFLAGS} /OPT:REF")
	else()
		set(CFLAGS "${CFLAGS} -ffunction-sections -fdata-sections")
		if(OPSYS STREQUAL "MACOSX")
			set(LFLAGS "${LFLAGS} -Wl,-dead_strip")
		else()
			set(LFLAGS "${LFLAGS} -Wl,--gc-sections")
		endif()
	endif()
endif()

# Flags given to CMake itself come last, so that they win. CMake derives the
# initial values from the environment, which CFLAGS and LFLAGS already hold,
# so only values that differ from those are the user's own.
string(STRIP "${CMAKE_C_FLAGS}" USER_CFLAGS)
string(STRIP "${CMAKE_C_FLAGS_INIT}" INIT_CFLAGS)
if("${USER_CFLAGS}" STREQUAL "${INIT_CFLAGS}")
	set(USER_CFLAGS "")
endif()
string(STRIP "${CMAKE_EXE_LINKER_FLAGS}" USER_LFLAGS)
string(STRIP "${CMAKE_EXE_LINKER_FLAGS_INIT}" INIT_LFLAGS)
if("${USER_LFLAGS}" STREQUAL "${INIT_LFLAGS}")
	set(USER_LFLAGS "")
endif()
set(CMAKE_C_FLAGS "${AFLAGS} ${WFLAGS} ${DFLAGS} ${CFLAGS}")
set(CMAKE_EXE_LINKER_FLAGS "${LFLAGS}")
if(USER_CFLAGS)
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${USER_CFLAGS}")
endif()
if(USER_LFLAGS)
	set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} ${USER_LFLAGS}")
endif()
if(CMAKE_BUILD_TYPE)
	message(STATUS "CMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE} adds its own flags, "
		"while RELIC chooses them through CFLAGS and DEBUG.")
endif()

message(STATUS "Compiler: ${CMAKE_C_COMPILER_ID} ${CMAKE_C_COMPILER_VERSION} (${CMAKE_C_COMPILER})")
message(STATUS "Compiler flags: ${CMAKE_C_FLAGS}")
message(STATUS "Linker flags: ${CMAKE_EXE_LINKER_FLAGS}")

# Keep the final flags as a C string for conf_print(), escaping backslashes
# and quotes and squeezing the spaces left by empty flag groups.
string(REGEX REPLACE " +" " " RLC_FLAGS "${CMAKE_C_FLAGS}")
string(STRIP "${RLC_FLAGS}" RLC_FLAGS)
string(REPLACE "\\" "\\\\" RLC_FLAGS "${RLC_FLAGS}")
string(REPLACE "\"" "\\\"" RLC_FLAGS "${RLC_FLAGS}")

# The header names these options and switches with a prefix.
foreach(OPT ARCH SEED MULTI TIMER OPSYS LABEL DEBUG CHECK VERBS DOCUM STRIP
		QUIET COLOR SHLIB STLIB)
	set(RLC_${OPT} "${${OPT}}")
endforeach()

set(ARITH_COPY ${ARITH})
string(TOUPPER ${ARITH} ARITH)
string(REPLACE "-" "_" ARITH ${ARITH})
string(REPLACE "." "_" ARITH ${ARITH})
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/include/relic_conf.h.in
	${CMAKE_CURRENT_BINARY_DIR}/include/relic_conf.h @ONLY)
message(STATUS "Configured ${CMAKE_CURRENT_SOURCE_DIR}/include/relic_conf.h.in with backend " ${ARITH_COPY})
set(ARITH ${ARITH_COPY})

if (LABEL)
	set(RELIC "relic_${LABEL}")
	set(RELIC_S "relic_s_${LABEL}")
else()
	set(RELIC "relic")
	set(RELIC_S "relic_s")
endif()

# Choose the label that prefixes the symbols of this build.
set(LABEL "" CACHE STRING "Build label")

add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/src)

file(GLOB includes "${CMAKE_CURRENT_SOURCE_DIR}/include/*.h")
install(FILES ${includes} DESTINATION include/${RELIC})
file(GLOB includes "${CMAKE_CURRENT_SOURCE_DIR}/include/low/*.h")
install(FILES ${includes} DESTINATION include/${RELIC}/low)
install(DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/include/" DESTINATION include/${RELIC})

install(FILES cmake/relic-config.cmake DESTINATION lib/cmake/relic)

if(DOCUM)
	include(cmake/doxygen.cmake)
endif()

if(TESTS GREATER 0)
	enable_testing()
	add_subdirectory(test)
endif(TESTS GREATER 0)

if(BENCH GREATER 0)
	add_subdirectory(bench)
endif(BENCH GREATER 0)
