# This file is installed in lib/cmake/relic, so the installation prefix is
# three levels up.
get_filename_component(RLC_PREFIX "${CMAKE_CURRENT_LIST_DIR}/../../.." ABSOLUTE)
find_path(RLC_INCLUDE_DIR relic/relic.h HINTS "${RLC_PREFIX}/include")
find_library(RLC_LIBRARY NAMES relic HINTS "${RLC_PREFIX}/lib")

include (FindPackageHandleStandardArgs)
find_package_handle_standard_args(relic DEFAULT_MSG RLC_INCLUDE_DIR RLC_LIBRARY)

if(relic_FOUND)
	set(RLC_LIBRARIES ${RLC_LIBRARY})
	set(RLC_INCLUDE_DIRS ${RLC_INCLUDE_DIR})
endif()
