# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.16

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:


#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:


# Remove some rules from gmake that .SUFFIXES does not remove.
SUFFIXES =

.SUFFIXES: .hpux_make_needs_suffix_list


# Suppress display of executed commands.
$(VERBOSE).SILENT:


# A target that is always out of date.
cmake_force:

.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/local/bin/cmake

# The command to remove a file.
RM = /usr/local/bin/cmake -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /opt/wireshark

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /opt/wireshark

# Utility rule file for generate_dissector-dcerpc-butc.

# Include the progress variables for this target.
include epan/dissectors/dcerpc/CMakeFiles/generate_dissector-dcerpc-butc.dir/progress.make

epan/dissectors/dcerpc/CMakeFiles/generate_dissector-dcerpc-butc: epan/dissectors/dcerpc/packet-dcerpc-butc-stamp


epan/dissectors/dcerpc/packet-dcerpc-butc-stamp: tools/pidl/pidl
epan/dissectors/dcerpc/packet-dcerpc-butc-stamp: epan/dissectors/dcerpc/butc/butc.idl
epan/dissectors/dcerpc/packet-dcerpc-butc-stamp: epan/dissectors/dcerpc/butc/butc.cnf
epan/dissectors/dcerpc/packet-dcerpc-butc-stamp: epan/dissectors/dcerpc/butc/packet-dcerpc-butc-template.h
epan/dissectors/dcerpc/packet-dcerpc-butc-stamp: epan/dissectors/dcerpc/butc/packet-dcerpc-butc-template.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --blue --bold --progress-dir=/opt/wireshark/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Generating packet-dcerpc-butc-stamp"
	cd /opt/wireshark/epan/dissectors/dcerpc/butc && /opt/wireshark/run/idl2wrs butc
	cd /opt/wireshark/epan/dissectors/dcerpc/butc && /usr/local/bin/cmake -E copy_if_different packet-dcerpc-butc.c /opt/wireshark/epan/dissectors/dcerpc/../packet-dcerpc-butc.c
	cd /opt/wireshark/epan/dissectors/dcerpc/butc && /usr/local/bin/cmake -E copy_if_different packet-dcerpc-butc.h /opt/wireshark/epan/dissectors/dcerpc/../packet-dcerpc-butc.h
	cd /opt/wireshark/epan/dissectors/dcerpc/butc && /usr/local/bin/cmake -E touch /opt/wireshark/epan/dissectors/dcerpc/packet-dcerpc-butc-stamp

generate_dissector-dcerpc-butc: epan/dissectors/dcerpc/CMakeFiles/generate_dissector-dcerpc-butc
generate_dissector-dcerpc-butc: epan/dissectors/dcerpc/packet-dcerpc-butc-stamp
generate_dissector-dcerpc-butc: epan/dissectors/dcerpc/CMakeFiles/generate_dissector-dcerpc-butc.dir/build.make

.PHONY : generate_dissector-dcerpc-butc

# Rule to build all files generated by this target.
epan/dissectors/dcerpc/CMakeFiles/generate_dissector-dcerpc-butc.dir/build: generate_dissector-dcerpc-butc

.PHONY : epan/dissectors/dcerpc/CMakeFiles/generate_dissector-dcerpc-butc.dir/build

epan/dissectors/dcerpc/CMakeFiles/generate_dissector-dcerpc-butc.dir/clean:
	cd /opt/wireshark/epan/dissectors/dcerpc && $(CMAKE_COMMAND) -P CMakeFiles/generate_dissector-dcerpc-butc.dir/cmake_clean.cmake
.PHONY : epan/dissectors/dcerpc/CMakeFiles/generate_dissector-dcerpc-butc.dir/clean

epan/dissectors/dcerpc/CMakeFiles/generate_dissector-dcerpc-butc.dir/depend:
	cd /opt/wireshark && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /opt/wireshark /opt/wireshark/epan/dissectors/dcerpc /opt/wireshark /opt/wireshark/epan/dissectors/dcerpc /opt/wireshark/epan/dissectors/dcerpc/CMakeFiles/generate_dissector-dcerpc-butc.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : epan/dissectors/dcerpc/CMakeFiles/generate_dissector-dcerpc-butc.dir/depend
