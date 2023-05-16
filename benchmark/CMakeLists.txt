set(bench_srcs
  ${CMAKE_CURRENT_SOURCE_DIR}/speed.c
  ${CMAKE_CURRENT_SOURCE_DIR}/cpucycles.c
  ${CMAKE_CURRENT_SOURCE_DIR}/speed_print.c
)

set(BENCH_NAME1 ${PROJECT_NAME}1-benchmark)
add_executable(${BENCH_NAME1} ${bench_srcs})
target_link_libraries(${BENCH_NAME1} ${LIB_NAME1})

set(BENCH_NAME3 ${PROJECT_NAME}3-benchmark)
add_executable(${BENCH_NAME3} ${bench_srcs})
target_link_libraries(${BENCH_NAME3} ${LIB_NAME3})

set(BENCH_NAME5 ${PROJECT_NAME}5-benchmark)
add_executable(${BENCH_NAME5} ${bench_srcs})
target_link_libraries(${BENCH_NAME5} ${LIB_NAME5})