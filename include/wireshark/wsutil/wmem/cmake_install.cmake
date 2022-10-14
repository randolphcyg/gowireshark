# Install script for directory: /opt/wireshark/wsutil/wmem

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
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/include/wireshark/wsutil/wmem" TYPE FILE FILES
    "/opt/wireshark/wsutil/wmem/wmem.h"
    "/opt/wireshark/wsutil/wmem/wmem_array.h"
    "/opt/wireshark/wsutil/wmem/wmem_core.h"
    "/opt/wireshark/wsutil/wmem/wmem_list.h"
    "/opt/wireshark/wsutil/wmem/wmem_map.h"
    "/opt/wireshark/wsutil/wmem/wmem_miscutl.h"
    "/opt/wireshark/wsutil/wmem/wmem_multimap.h"
    "/opt/wireshark/wsutil/wmem/wmem_queue.h"
    "/opt/wireshark/wsutil/wmem/wmem_stack.h"
    "/opt/wireshark/wsutil/wmem/wmem_strbuf.h"
    "/opt/wireshark/wsutil/wmem/wmem_strutl.h"
    "/opt/wireshark/wsutil/wmem/wmem_tree.h"
    "/opt/wireshark/wsutil/wmem/wmem_interval_tree.h"
    "/opt/wireshark/wsutil/wmem/wmem_user_cb.h"
    )
endif()

