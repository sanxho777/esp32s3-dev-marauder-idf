# Distributed under the OSI-approved BSD 3-Clause License.  See accompanying
# file Copyright.txt or https://cmake.org/licensing for details.

cmake_minimum_required(VERSION 3.5)

file(MAKE_DIRECTORY
  "/home/sandy/esp-idf/components/bootloader/subproject"
  "/home/sandy/esp32-marauder-idf/build/bootloader"
  "/home/sandy/esp32-marauder-idf/build/bootloader-prefix"
  "/home/sandy/esp32-marauder-idf/build/bootloader-prefix/tmp"
  "/home/sandy/esp32-marauder-idf/build/bootloader-prefix/src/bootloader-stamp"
  "/home/sandy/esp32-marauder-idf/build/bootloader-prefix/src"
  "/home/sandy/esp32-marauder-idf/build/bootloader-prefix/src/bootloader-stamp"
)

set(configSubDirs )
foreach(subDir IN LISTS configSubDirs)
    file(MAKE_DIRECTORY "/home/sandy/esp32-marauder-idf/build/bootloader-prefix/src/bootloader-stamp/${subDir}")
endforeach()
if(cfgdir)
  file(MAKE_DIRECTORY "/home/sandy/esp32-marauder-idf/build/bootloader-prefix/src/bootloader-stamp${cfgdir}") # cfgdir has leading slash
endif()
