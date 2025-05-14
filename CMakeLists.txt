#
# Copyright 2021 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

cmake_minimum_required(VERSION 3.10)

# set the project name
project(AEGIS VERSION 0.1)
set(CMAKE_CXX_STANDARD 17)

set(CMAKE_CXX_FLAGS "-O2 -msse2 -maes -msse3 -msse4.1")

find_package(absl REQUIRED)
find_package(jsoncpp REQUIRED)
find_package(GTest REQUIRED)
find_package(Threads REQUIRED) # Benchmark needs pthreads
find_package(benchmark REQUIRED) # Find the Google Benchmark package

enable_testing()

add_executable(aegis128L_test aegis128L.cc aegis128L_test.cc)
target_link_libraries(aegis128L_test gtest_main gtest absl::base absl::strings absl::random_random jsoncpp)
add_test(NAME aegis128L_test_test COMMAND aegis128L_test)

add_executable(aegis128L_benchmark aegis128L.cc aegis128L_benchmark.cc)
target_link_libraries(aegis128L_benchmark benchmark::benchmark benchmark::benchmark_main absl::base absl::strings absl::random_random Threads::Threads)
