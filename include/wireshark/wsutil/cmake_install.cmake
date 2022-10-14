# Install script for directory: /opt/wireshark/wsutil

# Set the install prefix
if(NOT DEFINED CMAKE_INSTALL_PREFIX)
  set(CMAKE_INSTALL_PREFIX "/usr/local")
endif()
string(REGEX REPLACE "/$" "" CMAKE_INSTALL_PREFIX "${CMAKE_INSTALL_PREFIX}")

# Set the install configuration name.
if(NOT DEFINED CMAKE_INSTALL_CONFIG_NAME)
  if(BUILD_TYPE)
    string(REGEX REPLACE "^[^A-Za-z0-9_]+" ""
           CMAKE_INSTALL_CONFIG_NAME "${BUILD_TYPE}")
  else()
    set(CMAKE_INSTALL_CONFIG_NAME "RelWithDebInfo")
  endif()
  message(STATUS "Install configuration: \"${CMAKE_INSTALL_CONFIG_NAME}\"")
endif()

# Set the component getting installed.
if(NOT CMAKE_INSTALL_COMPONENT)
  if(COMPONENT)
    message(STATUS "Install component: \"${COMPONENT}\"")
    set(CMAKE_INSTALL_COMPONENT "${COMPONENT}")
  else()
    set(CMAKE_INSTALL_COMPONENT)
  endif()
endif()

# Install shared libraries without execute permission?
if(NOT DEFINED CMAKE_INSTALL_SO_NO_EXE)
  set(CMAKE_INSTALL_SO_NO_EXE "1")
endif()

# Is this installation the result of a crosscompile?
if(NOT DEFINED CMAKE_CROSSCOMPILING)
  set(CMAKE_CROSSCOMPILING "FALSE")
endif()

if("x${CMAKE_INSTALL_COMPONENT}x" STREQUAL "xUnspecifiedx" OR NOT CMAKE_INSTALL_COMPONENT)
  foreach(file
      "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/libwsutil.so.14.0.0"
      "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/libwsutil.so.14"
      )
    if(EXISTS "${file}" AND
       NOT IS_SYMLINK "${file}")
      file(RPATH_CHECK
           FILE "${file}"
           RPATH "/usr/local/lib")
    endif()
  endforeach()
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib" TYPE SHARED_LIBRARY FILES
    "/opt/wireshark/run/libwsutil.so.14.0.0"
    "/opt/wireshark/run/libwsutil.so.14"
    )
  foreach(file
      "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/libwsutil.so.14.0.0"
      "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/libwsutil.so.14"
      )
    if(EXISTS "${file}" AND
       NOT IS_SYMLINK "${file}")
      file(RPATH_CHANGE
           FILE "${file}"
           OLD_RPATH "::::::::::::::"
           NEW_RPATH "/usr/local/lib")
      if(CMAKE_INSTALL_DO_STRIP)
        execute_process(COMMAND "/usr/bin/strip" "${file}")
      endif()
    endif()
  endforeach()
endif()

if("x${CMAKE_INSTALL_COMPONENT}x" STREQUAL "xUnspecifiedx" OR NOT CMAKE_INSTALL_COMPONENT)
  if(EXISTS "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/libwsutil.so" AND
     NOT IS_SYMLINK "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/libwsutil.so")
    file(RPATH_CHECK
         FILE "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/libwsutil.so"
         RPATH "/usr/local/lib")
  endif()
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib" TYPE SHARED_LIBRARY FILES "/opt/wireshark/run/libwsutil.so")
  if(EXISTS "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/libwsutil.so" AND
     NOT IS_SYMLINK "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/libwsutil.so")
    file(RPATH_CHANGE
         FILE "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/libwsutil.so"
         OLD_RPATH "::::::::::::::"
         NEW_RPATH "/usr/local/lib")
    if(CMAKE_INSTALL_DO_STRIP)
      execute_process(COMMAND "/usr/bin/strip" "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/libwsutil.so")
    endif()
  endif()
endif()

if("x${CMAKE_INSTALL_COMPONENT}x" STREQUAL "xUnspecifiedx" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/include/wireshark/wsutil" TYPE FILE FILES
    "/opt/wireshark/wsutil/802_11-utils.h"
    "/opt/wireshark/wsutil/adler32.h"
    "/opt/wireshark/wsutil/base32.h"
    "/opt/wireshark/wsutil/bits_count_ones.h"
    "/opt/wireshark/wsutil/bits_ctz.h"
    "/opt/wireshark/wsutil/bitswap.h"
    "/opt/wireshark/wsutil/buffer.h"
    "/opt/wireshark/wsutil/codecs.h"
    "/opt/wireshark/wsutil/color.h"
    "/opt/wireshark/wsutil/cpu_info.h"
    "/opt/wireshark/wsutil/crash_info.h"
    "/opt/wireshark/wsutil/crc5.h"
    "/opt/wireshark/wsutil/crc6.h"
    "/opt/wireshark/wsutil/crc7.h"
    "/opt/wireshark/wsutil/crc8.h"
    "/opt/wireshark/wsutil/crc10.h"
    "/opt/wireshark/wsutil/crc11.h"
    "/opt/wireshark/wsutil/crc16.h"
    "/opt/wireshark/wsutil/crc16-plain.h"
    "/opt/wireshark/wsutil/crc32.h"
    "/opt/wireshark/wsutil/curve25519.h"
    "/opt/wireshark/wsutil/eax.h"
    "/opt/wireshark/wsutil/epochs.h"
    "/opt/wireshark/wsutil/exported_pdu_tlvs.h"
    "/opt/wireshark/wsutil/feature_list.h"
    "/opt/wireshark/wsutil/filesystem.h"
    "/opt/wireshark/wsutil/g711.h"
    "/opt/wireshark/wsutil/inet_addr.h"
    "/opt/wireshark/wsutil/inet_ipv4.h"
    "/opt/wireshark/wsutil/inet_ipv6.h"
    "/opt/wireshark/wsutil/interface.h"
    "/opt/wireshark/wsutil/jsmn.h"
    "/opt/wireshark/wsutil/json_dumper.h"
    "/opt/wireshark/wsutil/mpeg-audio.h"
    "/opt/wireshark/wsutil/netlink.h"
    "/opt/wireshark/wsutil/nstime.h"
    "/opt/wireshark/wsutil/os_version_info.h"
    "/opt/wireshark/wsutil/pint.h"
    "/opt/wireshark/wsutil/please_report_bug.h"
    "/opt/wireshark/wsutil/pow2.h"
    "/opt/wireshark/wsutil/privileges.h"
    "/opt/wireshark/wsutil/processes.h"
    "/opt/wireshark/wsutil/regex.h"
    "/opt/wireshark/wsutil/report_message.h"
    "/opt/wireshark/wsutil/sign_ext.h"
    "/opt/wireshark/wsutil/sober128.h"
    "/opt/wireshark/wsutil/socket.h"
    "/opt/wireshark/wsutil/str_util.h"
    "/opt/wireshark/wsutil/strnatcmp.h"
    "/opt/wireshark/wsutil/strtoi.h"
    "/opt/wireshark/wsutil/tempfile.h"
    "/opt/wireshark/wsutil/time_util.h"
    "/opt/wireshark/wsutil/to_str.h"
    "/opt/wireshark/wsutil/type_util.h"
    "/opt/wireshark/wsutil/unicode-utils.h"
    "/opt/wireshark/wsutil/utf8_entities.h"
    "/opt/wireshark/wsutil/ws_assert.h"
    "/opt/wireshark/wsutil/ws_cpuid.h"
    "/opt/wireshark/wsutil/glib-compat.h"
    "/opt/wireshark/wsutil/ws_getopt.h"
    "/opt/wireshark/wsutil/ws_mempbrk.h"
    "/opt/wireshark/wsutil/ws_mempbrk_int.h"
    "/opt/wireshark/wsutil/ws_pipe.h"
    "/opt/wireshark/wsutil/ws_roundup.h"
    "/opt/wireshark/wsutil/ws_return.h"
    "/opt/wireshark/wsutil/wsgcrypt.h"
    "/opt/wireshark/wsutil/wsjson.h"
    "/opt/wireshark/wsutil/wslog.h"
    "/opt/wireshark/wsutil/xtea.h"
    )
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for each subdirectory.
  include("/opt/wireshark/wsutil/wmem/cmake_install.cmake")

endif()

