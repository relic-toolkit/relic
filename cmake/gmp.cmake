# Copyright (c) 2006, Laurent Montel, <montel@kde.org>
# Copyright (c) 2007, Francesco Biscani, <bluescarni@gmail.com>

# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
# 1. Redistributions of source code must retain the copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
# 3. The name of the author may not be used to endorse or promote products
#    derived from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
# OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
# IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
# NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
# THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
# ------------------------------------------------------------------------------------------

# Try to find the GMP libraries:
# GMP_FOUND - System has GMP lib
# GMP_INCLUDE_DIR - The GMP include directory
# GMP_LIBRARIES - Libraries needed to use GMP

# Search again only when an input of the search changes, since STBIN picks the
# static or the shared library, and keep the paths given by the user otherwise.
set(GMP_SEARCH "${STBIN};${GMP_ROOT};$ENV{GMP_ROOT}")
if(DEFINED GMP_SEARCHED AND NOT GMP_SEARCHED STREQUAL GMP_SEARCH)
	unset(GMP_INCLUDE_DIR CACHE)
	unset(GMP_LIBRARIES CACHE)
endif()
set(GMP_SEARCHED "${GMP_SEARCH}" CACHE INTERNAL "Inputs of the GMP search")

# Hints come before the system paths, so that GMP_ROOT takes precedence.
find_path(GMP_INCLUDE_DIR gmp.h
	HINTS
		${GMP_ROOT}
		ENV GMP_ROOT
		ENV GMP_INCLUDE_DIR
	PATHS
		/usr
		/usr/local
		/opt/homebrew
		/opt/local
		$ENV{HOME}/.local
	PATH_SUFFIXES
		include
)

if(STBIN)
	set(GMP_NAMES libgmp.a libgmp.dll.a gmp.lib libgmp-10 libgmp gmp)
else(STBIN)
	set(GMP_NAMES libgmp.so libgmp.dylib libgmp.dll.a gmp.lib libgmp-10
		libgmp gmp)
endif(STBIN)
find_library(GMP_LIBRARIES NAMES ${GMP_NAMES}
	HINTS
		${GMP_ROOT}
		ENV GMP_ROOT
	PATHS
		/usr
		/usr/local
		/opt/homebrew
		/opt/local
		$ENV{HOME}/.local
	PATH_SUFFIXES
		lib
		lib64
)

if(GMP_INCLUDE_DIR AND GMP_LIBRARIES)
   set(GMP_FOUND TRUE)
endif()

if(GMP_FOUND)
	message(STATUS "Configured GMP: -I${GMP_INCLUDE_DIR} -L${GMP_LIBRARIES}")
else(GMP_FOUND)
	# Only the backends that need GMP include this file.
	message(FATAL_ERROR "Could not find GMP, which ARITH=${ARITH} needs. "
		"Install it, or point GMP_ROOT to where it lives.")
endif(GMP_FOUND)

mark_as_advanced(GMP_INCLUDE_DIR GMP_LIBRARIES)
