cmake_minimum_required(VERSION 3.18)
project(smaug LANGUAGES C CXX) # CXX for google test

set(CMAKE_C_STANDARD 11)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib/)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib/)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin/)
set(EXECUTABLE_OUTPUT_PATH ${CMAKE_BINARY_DIR}/bin/)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

enable_testing()

include(cmake/CPM.cmake)
cpmaddpackage(
  NAME googletest
  GITHUB_REPOSITORY google/googletest
  GIT_TAG release-1.12.0
  VERSION 1.12.0
  OPTIONS "INSTALL_GTEST OFF" "gtest_force_shared_crt"
)

set(srcs
  ${PROJECT_SOURCE_DIR}/src/dg.c
  ${PROJECT_SOURCE_DIR}/src/pack.c
  ${PROJECT_SOURCE_DIR}/src/poly.c
  ${PROJECT_SOURCE_DIR}/src/key.c
  ${PROJECT_SOURCE_DIR}/src/ciphertext.c
  ${PROJECT_SOURCE_DIR}/src/hwt.c
  ${PROJECT_SOURCE_DIR}/src/kem.c
  ${PROJECT_SOURCE_DIR}/src/io.c
  ${PROJECT_SOURCE_DIR}/src/indcpa.c
  ${PROJECT_SOURCE_DIR}/src/hash.c
  ${PROJECT_SOURCE_DIR}/src/verify.c
)

if(MSVC)
  set(C_FLAGS /nologo /O2 /W4 /wd4146 /wd4244)
else()
  set(C_FLAGS -O3 -fomit-frame-pointer -fPIC -Wall -Wextra)
endif()


include_directories(${PROJECT_SOURCE_DIR}/include)

find_package(OpenSSL REQUIRED)
link_libraries(OpenSSL::Crypto)

set(LIB_RNG RNG)
add_library(${LIB_RNG} ${LIB_FIPS202} SHARED ${PROJECT_SOURCE_DIR}/src/rng.c)
target_compile_options(${LIB_RNG} PRIVATE ${C_FLAGS})

set(LIB_FIPS202 FIPS202)
add_library(${LIB_FIPS202} SHARED ${PROJECT_SOURCE_DIR}/src/fips202.c)
target_compile_options(${LIB_FIPS202} PRIVATE ${C_FLAGS})

set(LIB_NAME1 ${PROJECT_NAME}1)
add_library(${LIB_NAME1} SHARED ${srcs})
target_compile_definitions(${LIB_NAME1} PUBLIC SMAUG_MODE=1)
target_compile_options(${LIB_NAME1} PRIVATE ${C_FLAGS})
target_link_libraries(${LIB_NAME1} PUBLIC ${LIB_RNG} ${LIB_FIPS202})

set(LIB_NAME3 ${PROJECT_NAME}3)
add_library(${LIB_NAME3} SHARED ${srcs})
target_compile_definitions(${LIB_NAME3} PUBLIC SMAUG_MODE=3)
target_compile_options(${LIB_NAME3} PRIVATE ${C_FLAGS})
target_link_libraries(${LIB_NAME3} PUBLIC ${LIB_RNG} ${LIB_FIPS202})

set(LIB_NAME5 ${PROJECT_NAME}5)
add_library(${LIB_NAME5} SHARED ${srcs})
target_compile_definitions(${LIB_NAME5} PUBLIC SMAUG_MODE=5)
target_compile_options(${LIB_NAME5} PRIVATE ${C_FLAGS})
target_link_libraries(${LIB_NAME5} PUBLIC ${LIB_RNG} ${LIB_FIPS202})

add_subdirectory(test)
add_subdirectory(kat)
add_subdirectory(benchmark)
