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

# Utility rule file for generate_dissector-ieee1609dot2.

# Include the progress variables for this target.
include epan/dissectors/asn1/ieee1609dot2/CMakeFiles/generate_dissector-ieee1609dot2.dir/progress.make

epan/dissectors/asn1/ieee1609dot2/CMakeFiles/generate_dissector-ieee1609dot2: epan/dissectors/asn1/ieee1609dot2/packet-ieee1609dot2-stamp


epan/dissectors/asn1/ieee1609dot2/packet-ieee1609dot2-stamp: tools/asn2wrs.py
epan/dissectors/asn1/ieee1609dot2/packet-ieee1609dot2-stamp: epan/dissectors/asn1/ieee1609dot2/IEEE1609dot2BaseTypes.asn
epan/dissectors/asn1/ieee1609dot2/packet-ieee1609dot2-stamp: epan/dissectors/asn1/ieee1609dot2/IEEE1609dot2DataTypes.asn
epan/dissectors/asn1/ieee1609dot2/packet-ieee1609dot2-stamp: epan/dissectors/asn1/ieee1609dot2/IEEE1609dot12.asn
epan/dissectors/asn1/ieee1609dot2/packet-ieee1609dot2-stamp: epan/dissectors/asn1/ieee1609dot2/packet-ieee1609dot2-template.c
epan/dissectors/asn1/ieee1609dot2/packet-ieee1609dot2-stamp: epan/dissectors/asn1/ieee1609dot2/packet-ieee1609dot2-template.h
epan/dissectors/asn1/ieee1609dot2/packet-ieee1609dot2-stamp: epan/dissectors/asn1/ieee1609dot2/ieee1609dot2.cnf
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --blue --bold --progress-dir=/opt/wireshark/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Generating packet-ieee1609dot2-stamp"
	cd /opt/wireshark/epan/dissectors/asn1/ieee1609dot2 && /usr/bin/python3 /opt/wireshark/tools/asn2wrs.py -p ieee1609dot2 -c /opt/wireshark/epan/dissectors/asn1/ieee1609dot2/ieee1609dot2.cnf -s /opt/wireshark/epan/dissectors/asn1/ieee1609dot2/packet-ieee1609dot2-template -D /opt/wireshark/epan/dissectors/asn1/ieee1609dot2 -O /opt/wireshark/epan/dissectors IEEE1609dot2BaseTypes.asn IEEE1609dot2DataTypes.asn IEEE1609dot12.asn
	cd /opt/wireshark/epan/dissectors/asn1/ieee1609dot2 && /usr/bin/python3 -c "import shutil, sys; x,s,d=sys.argv; open(d, 'w'); shutil.copystat(s, d)" /opt/wireshark/epan/dissectors/packet-ieee1609dot2.c packet-ieee1609dot2-stamp

generate_dissector-ieee1609dot2: epan/dissectors/asn1/ieee1609dot2/CMakeFiles/generate_dissector-ieee1609dot2
generate_dissector-ieee1609dot2: epan/dissectors/asn1/ieee1609dot2/packet-ieee1609dot2-stamp
generate_dissector-ieee1609dot2: epan/dissectors/asn1/ieee1609dot2/CMakeFiles/generate_dissector-ieee1609dot2.dir/build.make

.PHONY : generate_dissector-ieee1609dot2

# Rule to build all files generated by this target.
epan/dissectors/asn1/ieee1609dot2/CMakeFiles/generate_dissector-ieee1609dot2.dir/build: generate_dissector-ieee1609dot2

.PHONY : epan/dissectors/asn1/ieee1609dot2/CMakeFiles/generate_dissector-ieee1609dot2.dir/build

epan/dissectors/asn1/ieee1609dot2/CMakeFiles/generate_dissector-ieee1609dot2.dir/clean:
	cd /opt/wireshark/epan/dissectors/asn1/ieee1609dot2 && $(CMAKE_COMMAND) -P CMakeFiles/generate_dissector-ieee1609dot2.dir/cmake_clean.cmake
.PHONY : epan/dissectors/asn1/ieee1609dot2/CMakeFiles/generate_dissector-ieee1609dot2.dir/clean

epan/dissectors/asn1/ieee1609dot2/CMakeFiles/generate_dissector-ieee1609dot2.dir/depend:
	cd /opt/wireshark && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /opt/wireshark /opt/wireshark/epan/dissectors/asn1/ieee1609dot2 /opt/wireshark /opt/wireshark/epan/dissectors/asn1/ieee1609dot2 /opt/wireshark/epan/dissectors/asn1/ieee1609dot2/CMakeFiles/generate_dissector-ieee1609dot2.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : epan/dissectors/asn1/ieee1609dot2/CMakeFiles/generate_dissector-ieee1609dot2.dir/depend
