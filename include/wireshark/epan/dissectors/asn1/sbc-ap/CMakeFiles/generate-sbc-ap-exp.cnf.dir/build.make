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

# Utility rule file for generate-sbc-ap-exp.cnf.

# Include the progress variables for this target.
include epan/dissectors/asn1/sbc-ap/CMakeFiles/generate-sbc-ap-exp.cnf.dir/progress.make

epan/dissectors/asn1/sbc-ap/CMakeFiles/generate-sbc-ap-exp.cnf: epan/dissectors/asn1/sbc-ap/sbc-ap-exp.cnf


epan/dissectors/asn1/sbc-ap/sbc-ap-exp.cnf: tools/asn2wrs.py
epan/dissectors/asn1/sbc-ap/sbc-ap-exp.cnf: epan/dissectors/asn1/sbc-ap/SBC-AP-CommonDataTypes.asn
epan/dissectors/asn1/sbc-ap/sbc-ap-exp.cnf: epan/dissectors/asn1/sbc-ap/SBC-AP-Constants.asn
epan/dissectors/asn1/sbc-ap/sbc-ap-exp.cnf: epan/dissectors/asn1/sbc-ap/SBC-AP-Containers.asn
epan/dissectors/asn1/sbc-ap/sbc-ap-exp.cnf: epan/dissectors/asn1/sbc-ap/SBC-AP-IEs.asn
epan/dissectors/asn1/sbc-ap/sbc-ap-exp.cnf: epan/dissectors/asn1/sbc-ap/SBC-AP-PDU-Contents.asn
epan/dissectors/asn1/sbc-ap/sbc-ap-exp.cnf: epan/dissectors/asn1/sbc-ap/SBC-AP-PDU-Descriptions.asn
epan/dissectors/asn1/sbc-ap/sbc-ap-exp.cnf: epan/dissectors/asn1/sbc-ap/packet-sbc-ap-template.c
epan/dissectors/asn1/sbc-ap/sbc-ap-exp.cnf: epan/dissectors/asn1/sbc-ap/sbc-ap.cnf
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --blue --bold --progress-dir=/opt/wireshark/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Generating sbc-ap-exp.cnf"
	cd /opt/wireshark/epan/dissectors/asn1/sbc-ap && /usr/bin/python3 /opt/wireshark/tools/asn2wrs.py -E -p sbc-ap -c /opt/wireshark/epan/dissectors/asn1/sbc-ap/sbc-ap.cnf -D /opt/wireshark/epan/dissectors/asn1/sbc-ap SBC-AP-CommonDataTypes.asn SBC-AP-Constants.asn SBC-AP-Containers.asn SBC-AP-IEs.asn SBC-AP-PDU-Contents.asn SBC-AP-PDU-Descriptions.asn

generate-sbc-ap-exp.cnf: epan/dissectors/asn1/sbc-ap/CMakeFiles/generate-sbc-ap-exp.cnf
generate-sbc-ap-exp.cnf: epan/dissectors/asn1/sbc-ap/sbc-ap-exp.cnf
generate-sbc-ap-exp.cnf: epan/dissectors/asn1/sbc-ap/CMakeFiles/generate-sbc-ap-exp.cnf.dir/build.make

.PHONY : generate-sbc-ap-exp.cnf

# Rule to build all files generated by this target.
epan/dissectors/asn1/sbc-ap/CMakeFiles/generate-sbc-ap-exp.cnf.dir/build: generate-sbc-ap-exp.cnf

.PHONY : epan/dissectors/asn1/sbc-ap/CMakeFiles/generate-sbc-ap-exp.cnf.dir/build

epan/dissectors/asn1/sbc-ap/CMakeFiles/generate-sbc-ap-exp.cnf.dir/clean:
	cd /opt/wireshark/epan/dissectors/asn1/sbc-ap && $(CMAKE_COMMAND) -P CMakeFiles/generate-sbc-ap-exp.cnf.dir/cmake_clean.cmake
.PHONY : epan/dissectors/asn1/sbc-ap/CMakeFiles/generate-sbc-ap-exp.cnf.dir/clean

epan/dissectors/asn1/sbc-ap/CMakeFiles/generate-sbc-ap-exp.cnf.dir/depend:
	cd /opt/wireshark && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /opt/wireshark /opt/wireshark/epan/dissectors/asn1/sbc-ap /opt/wireshark /opt/wireshark/epan/dissectors/asn1/sbc-ap /opt/wireshark/epan/dissectors/asn1/sbc-ap/CMakeFiles/generate-sbc-ap-exp.cnf.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : epan/dissectors/asn1/sbc-ap/CMakeFiles/generate-sbc-ap-exp.cnf.dir/depend
