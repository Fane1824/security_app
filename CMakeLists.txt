cmake_minimum_required(VERSION 2.6.4)
project(SECURITY_APP C)

# Find libgcrypt
find_package(PkgConfig REQUIRED)
pkg_check_modules(GCRYPT REQUIRED libgcrypt)

# Include cFS system definitions
include_directories(fsw/mission_inc)
include_directories(fsw/platform_inc)
include_directories(${cfs_lib_MISSION_DIR}/fsw/public_inc)
include_directories(${GCRYPT_INCLUDE_DIRS})

# Add the public headers
aux_source_directory(fsw/src APP_SRC_FILES)

# Create the app module
add_cfe_app(security_app ${APP_SRC_FILES})

# Add external dependencies
target_link_libraries(security_app ${GCRYPT_LIBRARIES})

# Add link directories for libgcrypt
link_directories(${GCRYPT_LIBRARY_DIRS})

# Add compiler flags for libgcrypt
add_definitions(${GCRYPT_CFLAGS_OTHER})