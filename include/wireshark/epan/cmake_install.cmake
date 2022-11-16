# Install script for directory: /opt/wireshark/epan

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
      "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/libwireshark.so.16.0.1"
      "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/libwireshark.so.16"
      )
    if(EXISTS "${file}" AND
       NOT IS_SYMLINK "${file}")
      file(RPATH_CHECK
           FILE "${file}"
           RPATH "/usr/local/lib")
    endif()
  endforeach()
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib" TYPE SHARED_LIBRARY FILES
    "/opt/wireshark/run/libwireshark.so.16.0.1"
    "/opt/wireshark/run/libwireshark.so.16"
    )
  foreach(file
      "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/libwireshark.so.16.0.1"
      "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/libwireshark.so.16"
      )
    if(EXISTS "${file}" AND
       NOT IS_SYMLINK "${file}")
      file(RPATH_CHANGE
           FILE "${file}"
           OLD_RPATH "\$ORIGIN:::::::"
           NEW_RPATH "/usr/local/lib")
      if(CMAKE_INSTALL_DO_STRIP)
        execute_process(COMMAND "/usr/bin/strip" "${file}")
      endif()
    endif()
  endforeach()
endif()

if("x${CMAKE_INSTALL_COMPONENT}x" STREQUAL "xUnspecifiedx" OR NOT CMAKE_INSTALL_COMPONENT)
  if(EXISTS "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/libwireshark.so" AND
     NOT IS_SYMLINK "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/libwireshark.so")
    file(RPATH_CHECK
         FILE "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/libwireshark.so"
         RPATH "/usr/local/lib")
  endif()
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib" TYPE SHARED_LIBRARY FILES "/opt/wireshark/run/libwireshark.so")
  if(EXISTS "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/libwireshark.so" AND
     NOT IS_SYMLINK "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/libwireshark.so")
    file(RPATH_CHANGE
         FILE "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/libwireshark.so"
         OLD_RPATH "\$ORIGIN:::::::"
         NEW_RPATH "/usr/local/lib")
    if(CMAKE_INSTALL_DO_STRIP)
      execute_process(COMMAND "/usr/bin/strip" "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/libwireshark.so")
    endif()
  endif()
endif()

if("x${CMAKE_INSTALL_COMPONENT}x" STREQUAL "xUnspecifiedx" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/include/wireshark/epan" TYPE FILE FILES
    "/opt/wireshark/epan/addr_and_mask.h"
    "/opt/wireshark/epan/addr_resolv.h"
    "/opt/wireshark/epan/address.h"
    "/opt/wireshark/epan/address_types.h"
    "/opt/wireshark/epan/afn.h"
    "/opt/wireshark/epan/aftypes.h"
    "/opt/wireshark/epan/app_mem_usage.h"
    "/opt/wireshark/epan/arcnet_pids.h"
    "/opt/wireshark/epan/arptypes.h"
    "/opt/wireshark/epan/asn1.h"
    "/opt/wireshark/epan/ax25_pids.h"
    "/opt/wireshark/epan/bridged_pids.h"
    "/opt/wireshark/epan/capture_dissectors.h"
    "/opt/wireshark/epan/charsets.h"
    "/opt/wireshark/epan/chdlctypes.h"
    "/opt/wireshark/epan/cisco_pid.h"
    "/opt/wireshark/epan/color_filters.h"
    "/opt/wireshark/epan/column.h"
    "/opt/wireshark/epan/column-info.h"
    "/opt/wireshark/epan/column-utils.h"
    "/opt/wireshark/epan/conversation.h"
    "/opt/wireshark/epan/conversation_debug.h"
    "/opt/wireshark/epan/conversation_table.h"
    "/opt/wireshark/epan/conv_id.h"
    "/opt/wireshark/epan/crc10-tvb.h"
    "/opt/wireshark/epan/crc16-tvb.h"
    "/opt/wireshark/epan/crc32-tvb.h"
    "/opt/wireshark/epan/crc6-tvb.h"
    "/opt/wireshark/epan/crc8-tvb.h"
    "/opt/wireshark/epan/decode_as.h"
    "/opt/wireshark/epan/diam_dict.h"
    "/opt/wireshark/epan/disabled_protos.h"
    "/opt/wireshark/epan/conversation_filter.h"
    "/opt/wireshark/epan/dccpservicecodes.h"
    "/opt/wireshark/epan/dtd.h"
    "/opt/wireshark/epan/dtd_parse.h"
    "/opt/wireshark/epan/dvb_chartbl.h"
    "/opt/wireshark/epan/eap.h"
    "/opt/wireshark/epan/eapol_keydes_types.h"
    "/opt/wireshark/epan/epan.h"
    "/opt/wireshark/epan/epan_dissect.h"
    "/opt/wireshark/epan/etypes.h"
    "/opt/wireshark/epan/ex-opt.h"
    "/opt/wireshark/epan/except.h"
    "/opt/wireshark/epan/exceptions.h"
    "/opt/wireshark/epan/expert.h"
    "/opt/wireshark/epan/export_object.h"
    "/opt/wireshark/epan/exported_pdu.h"
    "/opt/wireshark/epan/filter_expressions.h"
    "/opt/wireshark/epan/follow.h"
    "/opt/wireshark/epan/frame_data.h"
    "/opt/wireshark/epan/frame_data_sequence.h"
    "/opt/wireshark/epan/funnel.h"
    "/opt/wireshark/epan/golay.h"
    "/opt/wireshark/epan/guid-utils.h"
    "/opt/wireshark/epan/iana_charsets.h"
    "/opt/wireshark/epan/iax2_codec_type.h"
    "/opt/wireshark/epan/in_cksum.h"
    "/opt/wireshark/epan/introspection.h"
    "/opt/wireshark/epan/ip_opts.h"
    "/opt/wireshark/epan/ipproto.h"
    "/opt/wireshark/epan/ipv4.h"
    "/opt/wireshark/epan/ipv6.h"
    "/opt/wireshark/epan/lapd_sapi.h"
    "/opt/wireshark/epan/llcsaps.h"
    "/opt/wireshark/epan/maxmind_db.h"
    "/opt/wireshark/epan/media_params.h"
    "/opt/wireshark/epan/next_tvb.h"
    "/opt/wireshark/epan/nlpid.h"
    "/opt/wireshark/epan/oids.h"
    "/opt/wireshark/epan/osi-utils.h"
    "/opt/wireshark/epan/oui.h"
    "/opt/wireshark/epan/packet.h"
    "/opt/wireshark/epan/packet_info.h"
    "/opt/wireshark/epan/params.h"
    "/opt/wireshark/epan/pci-ids.h"
    "/opt/wireshark/epan/plugin_if.h"
    "/opt/wireshark/epan/ppptypes.h"
    "/opt/wireshark/epan/print.h"
    "/opt/wireshark/epan/print_stream.h"
    "/opt/wireshark/epan/prefs.h"
    "/opt/wireshark/epan/prefs-int.h"
    "/opt/wireshark/epan/proto.h"
    "/opt/wireshark/epan/proto_data.h"
    "/opt/wireshark/epan/ps.h"
    "/opt/wireshark/epan/ptvcursor.h"
    "/opt/wireshark/epan/range.h"
    "/opt/wireshark/epan/reassemble.h"
    "/opt/wireshark/epan/reedsolomon.h"
    "/opt/wireshark/epan/register.h"
    "/opt/wireshark/epan/req_resp_hdrs.h"
    "/opt/wireshark/epan/rtd_table.h"
    "/opt/wireshark/epan/rtp_pt.h"
    "/opt/wireshark/epan/sctpppids.h"
    "/opt/wireshark/epan/secrets.h"
    "/opt/wireshark/epan/show_exception.h"
    "/opt/wireshark/epan/slow_protocol_subtypes.h"
    "/opt/wireshark/epan/sminmpec.h"
    "/opt/wireshark/epan/srt_table.h"
    "/opt/wireshark/epan/stat_tap_ui.h"
    "/opt/wireshark/epan/stat_groups.h"
    "/opt/wireshark/epan/stats_tree.h"
    "/opt/wireshark/epan/stats_tree_priv.h"
    "/opt/wireshark/epan/stream.h"
    "/opt/wireshark/epan/strutil.h"
    "/opt/wireshark/epan/t35.h"
    "/opt/wireshark/epan/tap.h"
    "/opt/wireshark/epan/tap-voip.h"
    "/opt/wireshark/epan/timestamp.h"
    "/opt/wireshark/epan/timestats.h"
    "/opt/wireshark/epan/tfs.h"
    "/opt/wireshark/epan/to_str.h"
    "/opt/wireshark/epan/tvbparse.h"
    "/opt/wireshark/epan/tvbuff.h"
    "/opt/wireshark/epan/tvbuff-int.h"
    "/opt/wireshark/epan/uat.h"
    "/opt/wireshark/epan/uat-int.h"
    "/opt/wireshark/epan/unit_strings.h"
    "/opt/wireshark/epan/value_string.h"
    "/opt/wireshark/epan/wmem_scopes.h"
    "/opt/wireshark/epan/wscbor.h"
    "/opt/wireshark/epan/x264_prt_id.h"
    "/opt/wireshark/epan/xdlc.h"
    )
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for each subdirectory.
  include("/opt/wireshark/epan/crypt/cmake_install.cmake")
  include("/opt/wireshark/epan/dfilter/cmake_install.cmake")
  include("/opt/wireshark/epan/dissectors/cmake_install.cmake")
  include("/opt/wireshark/epan/ftypes/cmake_install.cmake")

endif()

